import json

from scripts.update_readme_stats import update_readme


def test_update_readme_stats_replaces_marker_block(tmp_path) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        "# RouteSentinel\n\n"
        "<!-- routesentinel-stats:start -->\n"
        "old stats\n"
        "<!-- routesentinel-stats:end -->\n"
    )
    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(
            {
                "total_announcements": 2000,
                "valid": 1200,
                "invalid": 50,
                "not_found": 750,
                "coverage_ratio": 0.6,
            }
        )
    )

    update_readme(
        readme,
        summary,
        "2026-05-23",
        release_url="https://github.com/example/routesentinel/releases/tag/2026-05-23",
        updated_at="2026-05-23 13:45 UTC",
    )

    updated = readme.read_text()
    assert "old stats" not in updated
    assert "Last successful snapshot: **2026-05-23**" in updated
    assert "[2026-05-23](https://github.com/example/routesentinel/releases/tag/2026-05-23)" in updated
    assert "Release updated: **2026-05-23 13:45 UTC**" in updated
    assert "| Total announcements | 2,000 |" in updated
    assert "| RPKI coverage ratio | 60.00% |" in updated
