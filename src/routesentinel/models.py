from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_network


class RpkiStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    NOT_FOUND = "not-found"


@dataclass(frozen=True, slots=True)
class Vrp:
    prefix: str
    max_length: int
    asn: int
    trust_anchor: str | None = None

    def __post_init__(self) -> None:
        network = ip_network(self.prefix, strict=False)
        if self.max_length < network.prefixlen:
            raise ValueError(f"max_length {self.max_length} is shorter than {self.prefix}")

    @property
    def network(self):
        return ip_network(self.prefix, strict=False)


@dataclass(frozen=True, slots=True)
class BgpAnnouncement:
    prefix: str
    origin_asn: int
    as_path: tuple[int, ...] = ()
    peer: str | None = None
    collector: str | None = None

    @property
    def network(self):
        return ip_network(self.prefix, strict=False)


@dataclass(frozen=True, slots=True)
class RpkiDecision:
    status: RpkiStatus
    announcement: BgpAnnouncement
    covering_vrps: tuple[Vrp, ...]

    @property
    def expected_origins(self) -> tuple[int, ...]:
        return tuple(sorted({vrp.asn for vrp in self.covering_vrps}))

