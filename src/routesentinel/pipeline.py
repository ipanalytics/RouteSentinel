from __future__ import annotations

import json
import csv
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


def write_summary_counts(
    counts: Counter[RpkiStatus],
    output: Path,
    unique_prefixes: int = 0,
    unique_invalid_prefixes: int = 0,
    top_invalid_asns: list[dict] | None = None,
    collectors: list[str] | None = None,
) -> Path:
    total = sum(counts.values())
    payload = {
        "total_announcements": total,
        "unique_prefixes": unique_prefixes,
        "unique_prefix_origin_pairs": total,
        "unique_invalid_prefixes": unique_invalid_prefixes,
        "valid": counts[RpkiStatus.VALID],
        "invalid": counts[RpkiStatus.INVALID],
        "not_found": counts[RpkiStatus.NOT_FOUND],
        "coverage_ratio": counts[RpkiStatus.VALID] / total if total else 0,
        "collectors": collectors or [],
        "top_invalid_asns": top_invalid_asns or [],
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


def write_top_invalid_asns(invalid_by_asn: Counter[int], output: Path, limit: int = 20) -> list[dict]:
    rows = [
        {"origin_asn": asn, "invalid_prefix_origin_pairs": count}
        for asn, count in invalid_by_asn.most_common(limit)
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["origin_asn", "invalid_prefix_origin_pairs"])
        writer.writeheader()
        writer.writerows(rows)
    return rows


def aggregate_route_origins(
    announcements: Iterable[BgpAnnouncement],
    progress: Progress | None = None,
) -> tuple[dict[tuple[str, int], set[str]], int, int]:
    route_origins: dict[tuple[str, int], set[str]] = defaultdict(set)
    rows_seen = 0
    for announcement in announcements:
        rows_seen += 1
        collector = announcement.collector or "unknown"
        route_origins[(announcement.prefix, announcement.origin_asn)].add(collector)
        if progress and rows_seen % 100_000 == 0:
            progress(
                "aggregate progress "
                f"rows_seen={rows_seen} unique_prefix_origin_pairs={len(route_origins)}"
            )
    duplicates = rows_seen - len(route_origins)
    if progress:
        progress(
            "aggregate done "
            f"rows_seen={rows_seen} unique_prefix_origin_pairs={len(route_origins)} "
            f"duplicates_collapsed={duplicates}"
        )
    return route_origins, rows_seen, duplicates


def stream_validate_snapshot(
    announcements: Iterable[BgpAnnouncement],
    vrp_json: Path,
    output_dir: Path,
    progress: Progress | None = None,
) -> None:
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
    if progress:
        progress("aggregate start key=prefix,origin_asn collectors=merged")
    route_origins, rows_seen, duplicates_skipped = aggregate_route_origins(
        announcements,
        progress=progress,
    )

    counts: Counter[RpkiStatus] = Counter()
    origins_by_prefix: dict[str, set[int]] = defaultdict(set)
    invalid_prefixes: set[str] = set()
    covered_prefixes: set[str] = set()
    unique_prefixes: set[str] = set()
    invalid_by_asn: Counter[int] = Counter()
    all_collectors: set[str] = set()
    invalid_path = output_dir / "rpki-invalids.csv"
    status_path = output_dir / "route-origin-status.csv"

    with invalid_path.open("w", newline="") as invalid_handle, status_path.open(
        "w", newline=""
    ) as status_handle:
        invalid_writer = csv.DictWriter(
            invalid_handle,
            fieldnames=[
                "prefix",
                "origin_asn",
                "status",
                "expected_origins",
                "collectors",
            ],
        )
        status_writer = csv.DictWriter(
            status_handle,
            fieldnames=[
                "prefix",
                "origin_asn",
                "status",
                "expected_origins",
                "collectors",
            ],
        )
        invalid_writer.writeheader()
        status_writer.writeheader()
        for count, ((prefix, origin_asn), collectors) in enumerate(
            sorted(route_origins.items()), start=1
        ):
            collector_list = sorted(collectors)
            all_collectors.update(collector_list)
            announcement = BgpAnnouncement(
                prefix=prefix,
                origin_asn=origin_asn,
                collector=" ".join(collector_list),
            )
            decision = index.validate(announcement)
            counts[decision.status] += 1
            origins_by_prefix[prefix].add(origin_asn)
            unique_prefixes.add(prefix)
            if decision.status in (RpkiStatus.VALID, RpkiStatus.INVALID):
                covered_prefixes.add(prefix)
            row = {
                "prefix": prefix,
                "origin_asn": origin_asn,
                "status": decision.status,
                "expected_origins": " ".join(map(str, decision.expected_origins)),
                "collectors": " ".join(collector_list),
            }
            status_writer.writerow(row)
            if decision.status == RpkiStatus.INVALID:
                invalid_prefixes.add(prefix)
                invalid_by_asn[origin_asn] += 1
                invalid_writer.writerow(row)
            if progress and count % 100_000 == 0:
                progress(
                    "validate progress "
                    f"rows_seen={rows_seen} unique_prefix_origin_pairs={count} "
                    f"duplicates_collapsed={duplicates_skipped} valid={counts[RpkiStatus.VALID]} "
                    f"invalid={counts[RpkiStatus.INVALID]} not_found={counts[RpkiStatus.NOT_FOUND]}"
                )

    if progress:
        progress(
            "validate done "
            f"rows_seen={rows_seen} unique_prefix_origin_pairs={sum(counts.values())} "
            f"duplicates_collapsed={duplicates_skipped} valid={counts[RpkiStatus.VALID]} "
            f"invalid={counts[RpkiStatus.INVALID]} not_found={counts[RpkiStatus.NOT_FOUND]}"
        )
        progress(f"write start output_dir={output_dir}")
    top_invalid_asns = write_top_invalid_asns(invalid_by_asn, output_dir / "top-invalid-asns.csv")
    write_summary_counts(
        counts,
        output_dir / "rpki-summary.json",
        unique_prefixes=len(unique_prefixes),
        unique_invalid_prefixes=len(invalid_prefixes),
        top_invalid_asns=top_invalid_asns,
        collectors=sorted(all_collectors),
    )
    with (output_dir / "rpki-covered-prefixes.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["prefix"])
        writer.writeheader()
        for prefix in sorted(covered_prefixes):
            writer.writerow({"prefix": prefix})
    write_suspected_events_from_maps(
        origins_by_prefix,
        invalid_prefixes,
        output_dir / "suspected-events.jsonl",
    )
    if progress:
        progress(
            "write done files=route-origin-status.csv,rpki-invalids.csv,"
            "rpki-summary.json,rpki-covered-prefixes.csv,top-invalid-asns.csv,"
            "suspected-events.jsonl"
        )


def run_snapshot(
    announcements_csv: Path | list[Path],
    vrp_json: Path,
    output_dir: Path,
    progress: Progress | None = None,
) -> None:
    paths = announcements_csv if isinstance(announcements_csv, list) else [announcements_csv]
    if progress:
        progress(f"announcements stream start paths={','.join(map(str, paths))}")

    def iter_all() -> Iterable[BgpAnnouncement]:
        for path in paths:
            yield from iter_announcements_csv(path)

    stream_validate_snapshot(
        iter_all(),
        vrp_json,
        output_dir,
        progress=progress,
    )
