from __future__ import annotations

import csv
import gzip
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Callable

import requests

from routesentinel.models import BgpAnnouncement, RpkiDecision


DEFAULT_USER_AGENT = "RouteSentinel/0.1"
Progress = Callable[[str], None]
AS_PATH_NUMBER = re.compile(r"\d+")


def download_file(
    url: str,
    output: Path,
    user_agent: str = DEFAULT_USER_AGENT,
    progress: Progress | None = None,
) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    if progress:
        progress(f"download start url={url} output={output}")
    with requests.get(url, headers={"User-Agent": user_agent}, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        content_length = int(resp.headers.get("content-length", "0") or 0)
        downloaded = 0
        next_report = 0
        with output.open("wb") as handle:
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
                            progress(f"download progress {downloaded / 1024 / 1024:.1f} MiB")
                        next_report = downloaded + 25 * 1024 * 1024
    if progress:
        progress(f"download done bytes={downloaded} output={output}")
    return output


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
