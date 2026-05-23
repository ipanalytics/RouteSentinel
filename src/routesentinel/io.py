from __future__ import annotations

import csv
import gzip
import subprocess
from collections.abc import Iterable
from pathlib import Path

import requests

from routesentinel.models import BgpAnnouncement, RpkiDecision


DEFAULT_USER_AGENT = "RouteSentinel/0.1 (+https://github.com/your-org/routesentinel)"


def download_file(url: str, output: Path, user_agent: str = DEFAULT_USER_AGENT) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, headers={"User-Agent": user_agent}, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        with output.open("wb") as handle:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    handle.write(chunk)
    return output


def read_announcements_csv(path: str | Path) -> list[BgpAnnouncement]:
    handle = gzip.open(path, "rt", newline="") if str(path).endswith(".gz") else open(path, newline="")
    with handle:
        reader = csv.DictReader(handle)
        return [
            BgpAnnouncement(
                prefix=row["prefix"],
                origin_asn=int(str(row["origin_asn"]).upper().removeprefix("AS")),
                as_path=tuple(int(item) for item in row.get("as_path", "").split() if item),
                peer=row.get("peer") or None,
                collector=row.get("collector") or None,
            )
            for row in reader
        ]


def parse_mrt_with_bgpdump(mrt_path: Path, output_csv: Path, collector: str) -> Path:
    """Convert an MRT RIB dump to normalized CSV using bgpdump.

    The parser expects bgpdump to be installed on the runner. It streams bgpdump's
    machine-readable output and keeps only the fields RouteSentinel needs for v1.
    """

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        ["bgpdump", "-m", str(mrt_path)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    with output_csv.open("w", newline="") as out:
        writer = csv.DictWriter(
            out, fieldnames=["prefix", "origin_asn", "as_path", "peer", "collector"]
        )
        writer.writeheader()
        for line in proc.stdout:
            fields = line.rstrip("\n").split("|")
            if len(fields) < 7 or fields[0] != "TABLE_DUMP2":
                continue
            peer = fields[3]
            prefix = fields[5]
            as_path = fields[6]
            if not as_path:
                continue
            origin = as_path.split()[-1].strip("{}").split(",")[0]
            writer.writerow(
                {
                    "prefix": prefix,
                    "origin_asn": origin,
                    "as_path": as_path,
                    "peer": peer,
                    "collector": collector,
                }
            )
    if proc.wait() != 0:
        raise RuntimeError(f"bgpdump failed for {mrt_path}")
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

