from routesentinel.models import BgpAnnouncement, RpkiStatus, Vrp
from routesentinel.rpki import VrpIndex


def test_valid_when_origin_matches_covering_vrp() -> None:
    index = VrpIndex([Vrp(prefix="203.0.113.0/24", max_length=24, asn=64496)])

    decision = index.validate(BgpAnnouncement(prefix="203.0.113.0/24", origin_asn=64496))

    assert decision.status == RpkiStatus.VALID


def test_invalid_when_origin_differs_from_covering_vrp() -> None:
    index = VrpIndex([Vrp(prefix="203.0.113.0/24", max_length=24, asn=64496)])

    decision = index.validate(BgpAnnouncement(prefix="203.0.113.0/24", origin_asn=64497))

    assert decision.status == RpkiStatus.INVALID
    assert decision.expected_origins == (64496,)


def test_not_found_when_no_covering_vrp_exists() -> None:
    index = VrpIndex([Vrp(prefix="203.0.113.0/24", max_length=24, asn=64496)])

    decision = index.validate(BgpAnnouncement(prefix="198.51.100.0/24", origin_asn=64497))

    assert decision.status == RpkiStatus.NOT_FOUND


def test_invalid_when_prefix_is_more_specific_than_max_length() -> None:
    index = VrpIndex([Vrp(prefix="203.0.113.0/23", max_length=23, asn=64496)])

    decision = index.validate(BgpAnnouncement(prefix="203.0.113.0/24", origin_asn=64496))

    assert decision.status == RpkiStatus.NOT_FOUND

