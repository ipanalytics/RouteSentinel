from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path

from routesentinel.io import read_announcements_csv, write_invalids_csv
from routesentinel.models import BgpAnnouncement, RpkiDecision, RpkiStatus
from routesentinel.rpki import VrpIndex, load_vrps_json

Progress = Callable[[str], None]


def validate_snapshot(
    announcements: list[BgpAnnouncement],
    vrp_path: Path,
    progress: Progress | None = None,
) -> list[RpkiDecision]:
    if progress:
        progress(f"vrp load start path={vrp_path}")
    vrps = load_vrps_json(vrp_path)
    if progress:
        progress(f"vrp load done vrps={len(vrps)}")
        progress("vrp index build start")
    index = VrpIndex(vrps)
    if progress:
        progress("vrp index build done")

    decisions: list[RpkiDecision] = []
    for count, announcement in enumerate(announcements, start=1):
        decisions.append(index.validate(announcement))
        if progress and count % 100_000 == 0:
            progress(f"validate progress announcements={count}")
    if progress:
        progress(f"validate done announcements={len(decisions)}")
    return decisions


def write_summary(decisions: list[RpkiDecision], output: Path) -> Path:
    counts = Counter(decision.status for decision in decisions)
    total = sum(counts.values())
    payload = {
        "total_announcements": total,
        "valid": counts[RpkiStatus.VALID],
        "invalid": counts[RpkiStatus.INVALID],
        "not_found": counts[RpkiStatus.NOT_FOUND],
        "coverage_ratio": counts[RpkiStatus.VALID] / total if total else 0,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return output


def write_suspected_events(decisions: list[RpkiDecision], output: Path) -> Path:
    origins_by_prefix: dict[str, set[int]] = defaultdict(set)
    invalid_prefixes: set[str] = set()
    for decision in decisions:
        origins_by_prefix[decision.announcement.prefix].add(decision.announcement.origin_asn)
        if decision.status == RpkiStatus.INVALID:
            invalid_prefixes.add(decision.announcement.prefix)

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w") as handle:
        for prefix, origins in sorted(origins_by_prefix.items()):
            if len(origins) < 2 and prefix not in invalid_prefixes:
                continue
            confidence = "medium" if prefix in invalid_prefixes else "low"
            handle.write(
                json.dumps(
                    {
                        "prefix": prefix,
                        "seen_origins": sorted(origins),
                        "signal": "multi-origin-invalid"
                        if prefix in invalid_prefixes and len(origins) > 1
                        else "rpki-invalid"
                        if prefix in invalid_prefixes
                        else "multi-origin",
                        "confidence": confidence,
                    },
                    sort_keys=True,
                )
                + "\n"
            )
    return output


def run_snapshot(
    announcements_csv: Path,
    vrp_json: Path,
    output_dir: Path,
    progress: Progress | None = None,
) -> None:
    if progress:
        progress(f"announcements load start path={announcements_csv}")
    announcements = read_announcements_csv(announcements_csv)
    if progress:
        progress(f"announcements load done announcements={len(announcements)}")
    decisions = validate_snapshot(announcements, vrp_json, progress=progress)
    if progress:
        progress(f"write start output_dir={output_dir}")
    write_invalids_csv(decisions, output_dir / "rpki-invalids.csv")
    write_summary(decisions, output_dir / "rpki-summary.json")
    write_suspected_events(decisions, output_dir / "suspected-events.jsonl")
    if progress:
        progress("write done files=rpki-invalids.csv,rpki-summary.json,suspected-events.jsonl")
