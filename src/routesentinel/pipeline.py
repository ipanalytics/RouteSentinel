from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path

from routesentinel.io import iter_announcements_csv, read_announcements_csv, write_invalids_csv
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


def write_summary_counts(counts: Counter[RpkiStatus], output: Path) -> Path:
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


def write_suspected_events_from_maps(
    origins_by_prefix: dict[str, set[int]],
    invalid_prefixes: set[str],
    output: Path,
) -> Path:
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


def write_invalid_decision(decision: RpkiDecision, writer) -> None:
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


def stream_validate_snapshot(
    announcements: Iterable[BgpAnnouncement],
    vrp_json: Path,
    output_dir: Path,
    progress: Progress | None = None,
) -> None:
    import csv

    if progress:
        progress(f"vrp load start path={vrp_json}")
    vrps = load_vrps_json(vrp_json)
    if progress:
        progress(f"vrp load done vrps={len(vrps)}")
        progress("vrp index build start")
    index = VrpIndex(vrps)
    if progress:
        progress("vrp index build done")

    output_dir.mkdir(parents=True, exist_ok=True)
    counts: Counter[RpkiStatus] = Counter()
    origins_by_prefix: dict[str, set[int]] = defaultdict(set)
    invalid_prefixes: set[str] = set()
    invalid_path = output_dir / "rpki-invalids.csv"

    with invalid_path.open("w", newline="") as handle:
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
        for count, announcement in enumerate(announcements, start=1):
            decision = index.validate(announcement)
            counts[decision.status] += 1
            origins_by_prefix[announcement.prefix].add(announcement.origin_asn)
            if decision.status == RpkiStatus.INVALID:
                invalid_prefixes.add(announcement.prefix)
                write_invalid_decision(decision, writer)
            if progress and count % 100_000 == 0:
                progress(
                    "validate progress "
                    f"announcements={count} valid={counts[RpkiStatus.VALID]} "
                    f"invalid={counts[RpkiStatus.INVALID]} not_found={counts[RpkiStatus.NOT_FOUND]}"
                )

    if progress:
        progress(
            "validate done "
            f"announcements={sum(counts.values())} valid={counts[RpkiStatus.VALID]} "
            f"invalid={counts[RpkiStatus.INVALID]} not_found={counts[RpkiStatus.NOT_FOUND]}"
        )
        progress(f"write start output_dir={output_dir}")
    write_summary_counts(counts, output_dir / "rpki-summary.json")
    write_suspected_events_from_maps(
        origins_by_prefix,
        invalid_prefixes,
        output_dir / "suspected-events.jsonl",
    )
    if progress:
        progress("write done files=rpki-invalids.csv,rpki-summary.json,suspected-events.jsonl")


def run_snapshot(
    announcements_csv: Path,
    vrp_json: Path,
    output_dir: Path,
    progress: Progress | None = None,
) -> None:
    if progress:
        progress(f"announcements stream start path={announcements_csv}")
    stream_validate_snapshot(
        iter_announcements_csv(announcements_csv),
        vrp_json,
        output_dir,
        progress=progress,
    )
