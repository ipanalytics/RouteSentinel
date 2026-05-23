from __future__ import annotations

import json
from collections import defaultdict
from ipaddress import ip_network
from pathlib import Path
from typing import Iterable

from routesentinel.models import BgpAnnouncement, RpkiDecision, RpkiStatus, Vrp


class VrpIndex:
    """Small in-memory VRP index optimized for batch snapshot validation."""

    def __init__(self, vrps: Iterable[Vrp]) -> None:
        self._by_version = {4: defaultdict(list), 6: defaultdict(list)}
        for vrp in vrps:
            network = vrp.network
            self._by_version[network.version][network.prefixlen].append(vrp)

    def covering(self, prefix: str) -> tuple[Vrp, ...]:
        announced = ip_network(prefix, strict=False)
        matches: list[Vrp] = []
        for prefix_len, candidates in self._by_version[announced.version].items():
            if prefix_len > announced.prefixlen:
                continue
            for vrp in candidates:
                vrp_network = vrp.network
                if announced.subnet_of(vrp_network) and announced.prefixlen <= vrp.max_length:
                    matches.append(vrp)
        return tuple(matches)

    def validate(self, announcement: BgpAnnouncement) -> RpkiDecision:
        covering = self.covering(announcement.prefix)
        if not covering:
            return RpkiDecision(RpkiStatus.NOT_FOUND, announcement, ())
        if any(vrp.asn == announcement.origin_asn for vrp in covering):
            return RpkiDecision(RpkiStatus.VALID, announcement, covering)
        return RpkiDecision(RpkiStatus.INVALID, announcement, covering)


def load_vrps_json(path: str | Path) -> list[Vrp]:
    data = json.loads(Path(path).read_text())
    rows = data.get("roas", data if isinstance(data, list) else [])
    vrps: list[Vrp] = []
    for row in rows:
        asn = row.get("asn", row.get("ASID", row.get("asid")))
        if isinstance(asn, str):
            asn = asn.upper().removeprefix("AS")
        max_length = row.get("maxLength", row.get("max_length", row.get("maxlen")))
        trust_anchor = row.get("ta", row.get("trustAnchor", row.get("trust_anchor")))
        vrps.append(
            Vrp(
                prefix=row["prefix"],
                max_length=int(max_length),
                asn=int(asn),
                trust_anchor=trust_anchor,
            )
        )
    return vrps

