from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path


START_MARKER = "<!-- routesentinel-stats:start -->"
END_MARKER = "<!-- routesentinel-stats:end -->"


def format_int(value: int) -> str:
    return f"{value:,}"


def format_percent(value: float) -> str:
    return f"{value * 100:.2f}%"


def render_stats(
    summary: dict,
    run_date: str,
    release_url: str | None = None,
    updated_at: str | None = None,
) -> str:
    generated_at = updated_at or datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    total = int(summary.get("total_announcements", 0))
    valid = int(summary.get("valid", 0))
    invalid = int(summary.get("invalid", 0))
    not_found = int(summary.get("not_found", 0))
    coverage_ratio = float(summary.get("coverage_ratio", 0))
    if release_url:
        release_line = f"Release assets: [{run_date}]({release_url})"
    else:
        release_line = f"Release assets: **{run_date}**"

    return "\n".join(
        [
            START_MARKER,
            f"Last successful snapshot: **{run_date}**",
            release_line,
            f"Release updated: **{generated_at}**",
            "",
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Total announcements | {format_int(total)} |",
            f"| RPKI valid | {format_int(valid)} |",
            f"| RPKI invalid | {format_int(invalid)} |",
            f"| RPKI not-found | {format_int(not_found)} |",
            f"| RPKI coverage ratio | {format_percent(coverage_ratio)} |",
            "",
            "_This block is updated after the GitHub Release is successfully published._",
            END_MARKER,
        ]
    )


def update_readme(
    readme_path: Path,
    summary_path: Path,
    run_date: str,
    release_url: str | None = None,
    updated_at: str | None = None,
) -> None:
    readme = readme_path.read_text()
    summary = json.loads(summary_path.read_text())
    replacement = render_stats(summary, run_date, release_url=release_url, updated_at=updated_at)

    if START_MARKER not in readme or END_MARKER not in readme:
        raise ValueError(f"README must contain {START_MARKER} and {END_MARKER}")

    before, rest = readme.split(START_MARKER, 1)
    _, after = rest.split(END_MARKER, 1)
    readme_path.write_text(before + replacement + after)


def main() -> None:
    parser = argparse.ArgumentParser(description="Update README RouteSentinel stats block.")
    parser.add_argument("--readme", type=Path, default=Path("README.md"))
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--date", default=datetime.now(UTC).strftime("%Y-%m-%d"))
    parser.add_argument("--release-url")
    parser.add_argument("--updated-at")
    args = parser.parse_args()

    update_readme(
        args.readme,
        args.summary,
        args.date,
        release_url=args.release_url,
        updated_at=args.updated_at,
    )


if __name__ == "__main__":
    main()
