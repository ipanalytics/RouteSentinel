import json

from scripts.build_changelog import build_diff, main, read_status


def test_build_diff_detects_daily_changes(tmp_path) -> None:
    previous = tmp_path / "previous.csv"
    previous.write_text(
        "prefix,origin_asn,status,expected_origins,collectors\n"
        "203.0.113.0/24,64496,invalid,64500,rrc00\n"
        "198.51.100.0/24,64497,valid,64497,rrc00\n"
        "192.0.2.0/24,64498,not-found,,rrc00\n"
    )
    current = tmp_path / "current.csv"
    current.write_text(
        "prefix,origin_asn,status,expected_origins,collectors\n"
        "203.0.113.0/24,64496,valid,64496,rrc00\n"
        "198.51.100.0/24,64497,valid,64497,rrc00\n"
        "198.51.100.0/24,64500,invalid,64497,rrc00\n"
        "192.0.2.0/24,64498,valid,64498,rrc00\n"
    )

    diff = build_diff(read_status(current), read_status(previous))

    assert diff["counts"]["new_invalids"] == 1
    assert diff["counts"]["resolved_invalids"] == 1
    assert diff["counts"]["new_origin_asns"] == 1
    assert diff["counts"]["newly_rpki_covered_prefixes"] == 1
    assert json.dumps(diff)


def test_changelog_without_previous_state_is_baseline(tmp_path, monkeypatch) -> None:
    current = tmp_path / "current.csv"
    current.write_text(
        "prefix,origin_asn,status,expected_origins,collectors\n"
        "203.0.113.0/24,64496,invalid,64500,rrc00\n"
    )
    summary = tmp_path / "summary.json"
    summary.write_text(
        json.dumps(
            {
                "collectors": ["rrc00"],
                "coverage_ratio": 0,
                "invalid": 1,
                "not_found": 0,
                "total_announcements": 1,
                "unique_invalid_prefixes": 1,
                "unique_prefix_origin_pairs": 1,
                "unique_prefixes": 1,
                "valid": 0,
            }
        )
    )
    out_md = tmp_path / "changelog.md"
    out_json = tmp_path / "daily-diff.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "build_changelog.py",
            "--current-status",
            str(current),
            "--current-summary",
            str(summary),
            "--previous-status",
            str(tmp_path / "missing.csv"),
            "--date",
            "2026-05-23",
            "--out-md",
            str(out_md),
            "--out-json",
            str(out_json),
        ],
    )

    main()

    diff = json.loads(out_json.read_text())
    assert diff["counts"]["new_invalids"] == 0
    assert "baseline" in out_md.read_text()
