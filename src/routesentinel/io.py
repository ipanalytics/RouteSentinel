from __future__ import annotations

import csv
import gzip
import os
import re
import subprocess
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Callable

import requests

from routesentinel.models import BgpAnnouncement, RpkiDecision


DEFAULT_USER_AGENT = "RouteSentinel/0.1"
DEFAULT_RETRIES = 3
RETRY_BACKOFF_SECONDS = 5.0
JSON_TAIL_WINDOW = 4096
Progress = Callable[[str], None]
AS_PATH_NUMBER = re.compile(r"\d+")


class DownloadIntegrityError(RuntimeError):
    """The payload arrived shorter than the server announced (or is not valid JSON)."""


def _json_tail_is_closed(path: Path) -> bool:
    """Cheap truncation check for JSON dumps: the document must end with } or ]."""

    size = path.stat().st_size
    if size == 0:
        return False
    with path.open("rb") as handle:
        handle.seek(max(0, size - JSON_TAIL_WINDOW))
        tail = handle.read().rstrip()
    return tail.endswith((b"}", b"]"))


def _fetch_once(
    url: str,
    output: Path,
    user_agent: str,
    progress: Progress | None,
) -> Path:
    """Single download attempt: stream into a .part file, verify, then replace atomically."""

    partial = output.with_name(output.name + ".part")
    downloaded = 0
    content_length = 0
    try:
        with requests.get(
            url, headers={"User-Agent": user_agent}, stream=True, timeout=120
        ) as resp:
            resp.raise_for_status()
            content_length = int(resp.headers.get("content-length", "0") or 0)
            next_report = 0
            with partial.open("wb") as handle:
                for chunk in resp.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        handle.write(chunk)
                        downloaded += len(chunk)
                        if progress and downloaded >= next_report:
                            if content_length:
                                percent = downloaded / content_length * 100
                                progress(
                                    "download progress "
                                    f"{downloaded / 1024 / 1024:.1f} MiB / "
                                    f"{content_length / 1024 / 1024:.1f} MiB ({percent:.1f}%)"
                                )
                            else:
                                progress(
                                    f"download progress {downloaded / 1024 / 1024:.1f} MiB"
                                )
                            next_report = downloaded + 25 * 1024 * 1024
                handle.flush()
                os.fsync(handle.fileno())
        if content_length and downloaded != content_length:
            raise DownloadIntegrityError(
                f"short read for {url}: {downloaded} of {content_length} bytes"
            )
        if output.suffix.lower() == ".json" and not _json_tail_is_closed(partial):
            raise DownloadIntegrityError(
                f"truncated JSON for {url}: {partial.stat().st_size} bytes arrive "
                "but the document never closes"
            )
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    os.replace(partial, output)
    if progress:
        progress(f"download done bytes={downloaded} output={output}")
    return output


def download_file(
    url: str,
    output: Path,
    user_agent: str = DEFAULT_USER_AGENT,
    progress: Progress | None = None,
    retries: int = DEFAULT_RETRIES,
) -> Path:
    """Download a source dump, retrying transient failures and never keeping a short read.

    A truncated body used to land directly in ``output`` and blow up much later inside the
    snapshot step; now every attempt goes to ``<output>.part``, is checked against the
    advertised Content-Length (and the JSON tail for ``.json`` targets), and only then
    replaces the target file. Client errors (4xx) are not retried.
    """

    output.parent.mkdir(parents=True, exist_ok=True)
    if progress:
        progress(f"download start url={url} output={output}")
    attempts = max(1, int(retries))
    for attempt in range(1, attempts + 1):
        try:
            return _fetch_once(url, output, user_agent, progress)
        except Exception as exc:  # classified just below
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status is not None and 400 <= status < 500 and status != 429:
                raise
            if attempt == attempts:
                if progress:
                    progress(f"download failed after {attempts} attempts url={url} error={exc}")
                raise
            wait = RETRY_BACKOFF_SECONDS * attempt
            if progress:
                progress(
                    f"download attempt {attempt}/{attempts} failed url={url} "
                    f"error={type(exc).__name__}: {exc} - retrying in {wait:.0f}s"
                )
            time.sleep(wait)
    raise AssertionError("unreachable")


def parse_as_path(value: str) -> tuple[int, ...]:
    return tuple(int(match) for match in AS_PATH_NUMBER.findall(value or ""))


def iter_announcements_csv(path: str | Path) -> Iterable[BgpAnnouncement]:
    handle = gzip.open(path, "rt", newline="") if str(path).endswith(".gz") else open(path, newline="")
    with handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield BgpAnnouncement(
                prefix=row["prefix"],
                origin_asn=int(str(row["origin_asn"]).upper().removeprefix("AS")),
                as_path=parse_as_path(row.get("as_path", "")),
                peer=row.get("peer") or None,
                collector=row.get("collector") or None,
            )


def read_announcements_csv(path: str | Path) -> list[BgpAnnouncement]:
    return list(iter_announcements_csv(path))


def parse_mrt_with_bgpdump(
    mrt_path: Path,
    output_csv: Path,
    collector: str,
    progress: Progress | None = None,
    dedupe: bool = True,
) -> Path:
    """Convert an MRT RIB dump to normalized CSV using bgpdump.

    The parser expects bgpdump to be installed on the runner. It streams bgpdump's
    machine-readable output and keeps only the fields RouteSentinel needs for v1.
    """

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if progress:
        progress(f"parse start mrt={mrt_path} collector={collector} output={output_csv}")
    proc = subprocess.Popen(
        ["bgpdump", "-m", str(mrt_path)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    lines_seen = 0
    raw_rows = 0
    rows_written = 0
    duplicates_skipped = 0
    seen: set[tuple[str, str, str]] = set()
    with output_csv.open("w", newline="") as out:
        writer = csv.DictWriter(
            out, fieldnames=["prefix", "origin_asn", "as_path", "peer", "collector"]
        )
        writer.writeheader()
        for line in proc.stdout:
            lines_seen += 1
            if progress and lines_seen % 100_000 == 0:
                progress(
                    "parse progress "
                    f"bgpdump_lines={lines_seen} raw_announcements={raw_rows} "
                    f"unique_announcements={rows_written} duplicates_skipped={duplicates_skipped}"
                )
            fields = line.rstrip("\n").split("|")
            if len(fields) < 7 or fields[0] != "TABLE_DUMP2":
                continue
            peer = fields[3]
            prefix = fields[5]
            as_path = fields[6]
            if not as_path:
                continue
            origin = as_path.split()[-1].strip("{}").split(",")[0]
            raw_rows += 1
            key = (prefix, origin, collector)
            if dedupe and key in seen:
                duplicates_skipped += 1
                continue
            seen.add(key)
            writer.writerow(
                {
                    "prefix": prefix,
                    "origin_asn": origin,
                    "as_path": as_path,
                    "peer": peer,
                    "collector": collector,
                }
            )
            rows_written += 1
    if proc.wait() != 0:
        raise RuntimeError(f"bgpdump failed for {mrt_path}")
    if progress:
        progress(
            "parse done "
            f"bgpdump_lines={lines_seen} raw_announcements={raw_rows} "
            f"unique_announcements={rows_written} duplicates_skipped={duplicates_skipped}"
        )
    return output_csv


def write_invalids_csv(decisions: Iterable[RpkiDecision], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "prefix",
                "origin_asn",
                "status",
                "expected_origins",
                "collector",
                "peer",
            ],
        )
        writer.writeheader()
        for decision in decisions:
            if decision.status != "invalid":
                continue
            writer.writerow(
                {
                    "prefix": decision.announcement.prefix,
                    "origin_asn": decision.announcement.origin_asn,
                    "status": decision.status,
                    "expected_origins": " ".join(map(str, decision.expected_origins)),
                    "collector": decision.announcement.collector or "",
                    "peer": decision.announcement.peer or "",
                }
            )
    return output
