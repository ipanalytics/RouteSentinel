from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path


def read_status(path: Path) -> dict[tuple[str, int], dict]:
    if not path.exists():
        return {}
    rows: dict[tuple[str, int], dict] = {}
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            key = (row["prefix"], int(row["origin_asn"]))
            rows[key] = row
    return rows


def prefix_origins(rows: dict[tuple[str, int], dict]) -> dict[str, set[int]]:
    origins: dict[str, set[int]] = defaultdict(set)
    for prefix, origin_asn in rows:
        origins[prefix].add(origin_asn)
    return origins


def covered_prefixes(rows: dict[tuple[str, int], dict]) -> set[str]:
    return {
        prefix
        for (prefix, _), row in rows.items()
        if row["status"] in {"valid", "invalid"}
    }


def invalids(rows: dict[tuple[str, int], dict]) -> set[tuple[str, int]]:
    return {key for key, row in rows.items() if row["status"] == "invalid"}


def limit_rows(rows: list[dict], limit: int) -> list[dict]:
    return rows[:limit]


def build_diff(current: dict[tuple[str, int], dict], previous: dict[tuple[str, int], dict]) -> dict:
    current_invalids = invalids(current)
    previous_invalids = invalids(previous)
    current_origins = prefix_origins(current)
    previous_origins = prefix_origins(previous)
    current_covered = covered_prefixes(current)
    previous_covered = covered_prefixes(previous)

    new_invalids = [
        {
            "prefix": prefix,
            "origin_asn": origin_asn,
            "expected_origins": current[(prefix, origin_asn)].get("expected_origins", ""),
            "collectors": current[(prefix, origin_asn)].get("collectors", ""),
        }
        for prefix, origin_asn in sorted(current_invalids - previous_invalids)
    ]
    resolved_invalids = [
        {
            "prefix": prefix,
            "origin_asn": origin_asn,
        }
        for prefix, origin_asn in sorted(previous_invalids - current_invalids)
    ]

    new_origin_asns = []
    for prefix, origins in sorted(current_origins.items()):
        previous_for_prefix = previous_origins.get(prefix, set())
        for origin_asn in sorted(origins - previous_for_prefix):
            new_origin_asns.append(
                {
                    "prefix": prefix,
                    "new_origin_asn": origin_asn,
                    "current_origins": sorted(origins),
                    "previous_origins": sorted(previous_for_prefix),
                }
            )

    newly_covered_prefixes = [
        {"prefix": prefix} for prefix in sorted(current_covered - previous_covered)
    ]

    return {
        "new_invalids": new_invalids,
        "resolved_invalids": resolved_invalids,
        "new_origin_asns": new_origin_asns,
        "newly_rpki_covered_prefixes": newly_covered_prefixes,
        "counts": {
            "new_invalids": len(new_invalids),
            "resolved_invalids": len(resolved_invalids),
            "new_origin_asns": len(new_origin_asns),
            "newly_rpki_covered_prefixes": len(newly_covered_prefixes),
        },
    }


def render_table(rows: list[dict], columns: list[str], limit: int = 20) -> list[str]:
    if not rows:
        return ["None."]
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    for row in limit_rows(rows, limit):
        lines.append("| " + " | ".join(str(row.get(column, "")) for column in columns) + " |")
    if len(rows) > limit:
        lines.append(f"\nShowing {limit} of {len(rows)} rows. See `daily-diff.json` for full data.")
    return lines


def render_markdown(
    run_date: str,
    generated_at: str,
    summary: dict,
    diff: dict,
    previous_available: bool,
) -> str:
    lines = [
        f"# RouteSentinel {run_date}",
        "",
        f"Release updated: {generated_at}",
        "",
        "Daily route-origin security snapshot from public BGP collectors and VRP JSON.",
        "",
        "## Snapshot Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Collectors | {', '.join(summary.get('collectors', [])) or 'unknown'} |",
        f"| Unique prefixes | {summary.get('unique_prefixes', 0):,} |",
        f"| Unique prefix-origin pairs | {summary.get('unique_prefix_origin_pairs', 0):,} |",
        f"| RPKI valid | {summary.get('valid', 0):,} |",
        f"| RPKI invalid | {summary.get('invalid', 0):,} |",
        f"| Unique invalid prefixes | {summary.get('unique_invalid_prefixes', 0):,} |",
        f"| RPKI not-found | {summary.get('not_found', 0):,} |",
        f"| RPKI coverage ratio | {summary.get('coverage_ratio', 0) * 100:.2f}% |",
        "",
        "## Daily Diff",
        "",
    ]
    if not previous_available:
        lines.extend(
            [
                "No previous `route-origin-status.csv` was available, so this release is the baseline.",
                "",
            ]
        )
    counts = diff["counts"]
    lines.extend(
        [
            "| Signal | Count |",
            "| --- | ---: |",
            f"| New RPKI-invalid prefix-origin pairs | {counts['new_invalids']:,} |",
            f"| Resolved RPKI-invalid prefix-origin pairs | {counts['resolved_invalids']:,} |",
            f"| New origin ASNs for existing/new prefixes | {counts['new_origin_asns']:,} |",
            f"| Newly RPKI-covered prefixes | {counts['newly_rpki_covered_prefixes']:,} |",
            "",
            "### New RPKI Invalids",
            "",
            *render_table(
                diff["new_invalids"],
                ["prefix", "origin_asn", "expected_origins", "collectors"],
            ),
            "",
            "### Resolved RPKI Invalids",
            "",
            *render_table(diff["resolved_invalids"], ["prefix", "origin_asn"]),
            "",
            "### New Origin ASNs",
            "",
            *render_table(
                diff["new_origin_asns"],
                ["prefix", "new_origin_asn", "previous_origins", "current_origins"],
            ),
            "",
            "### Newly RPKI-Covered Prefixes",
            "",
            *render_table(diff["newly_rpki_covered_prefixes"], ["prefix"]),
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build RouteSentinel daily changelog.")
    parser.add_argument("--current-status", type=Path, required=True)
    parser.add_argument("--current-summary", type=Path, required=True)
    parser.add_argument("--previous-status", type=Path)
    parser.add_argument("--date", required=True)
    parser.add_argument("--updated-at", default=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"))
    parser.add_argument("--out-md", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, required=True)
    args = parser.parse_args()

    current = read_status(args.current_status)
    previous = read_status(args.previous_status) if args.previous_status else {}
    previous_available = bool(previous)
    summary = json.loads(args.current_summary.read_text())
    diff = build_diff(current, previous if previous_available else current)

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(diff, indent=2, sort_keys=True) + "\n")
    args.out_md.write_text(
        render_markdown(args.date, args.updated_at, summary, diff, previous_available)
    )


if __name__ == "__main__":
    main()
