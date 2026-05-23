import json

from routesentinel.pipeline import run_snapshot


def test_run_snapshot_writes_core_outputs(tmp_path) -> None:
    announcements = tmp_path / "announcements.csv"
    announcements.write_text(
        "prefix,origin_asn,as_path,peer,collector\n"
        "203.0.113.0/24,64496,64497 64496,192.0.2.1,rrc00\n"
        "198.51.100.0/24,64499,64498 64499,192.0.2.2,rrc00\n"
    )
    vrps = tmp_path / "vrps.json"
    vrps.write_text(
        json.dumps(
            {
                "roas": [
                    {"prefix": "203.0.113.0/24", "maxLength": 24, "asn": "AS64496"},
                    {"prefix": "198.51.100.0/24", "maxLength": 24, "asn": 64500},
                ]
            }
        )
    )

    run_snapshot(announcements, vrps, tmp_path / "out")

    summary = json.loads((tmp_path / "out" / "rpki-summary.json").read_text())
    assert summary["valid"] == 1
    assert summary["invalid"] == 1
    assert "198.51.100.0/24" in (tmp_path / "out" / "rpki-invalids.csv").read_text()
    assert "rpki-invalid" in (tmp_path / "out" / "suspected-events.jsonl").read_text()


def test_run_snapshot_accepts_as_set_in_as_path(tmp_path) -> None:
    announcements = tmp_path / "announcements.csv"
    announcements.write_text(
        "prefix,origin_asn,as_path,peer,collector\n"
        "203.0.113.0/24,6877,64500 {6877},192.0.2.1,rrc00\n"
    )
    vrps = tmp_path / "vrps.json"
    vrps.write_text(
        json.dumps(
            {
                "roas": [
                    {"prefix": "203.0.113.0/24", "maxLength": 24, "asn": "AS6877"},
                ]
            }
        )
    )

    run_snapshot(announcements, vrps, tmp_path / "out")

    summary = json.loads((tmp_path / "out" / "rpki-summary.json").read_text())
    assert summary["valid"] == 1
    assert summary["invalid"] == 0
