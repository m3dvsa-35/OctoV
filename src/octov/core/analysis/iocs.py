"""Indicators of compromise derived from classified strings."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from octov.core.analysis.strings import FoundString

IOC_TYPES = frozenset(
    {
        "url",
        "ipv4",
        "ipv6",
        "domain",
        "email",
        "registry",
        "mutex",
        "path",
        "user_agent",
        "wallet",
        "command",
    }
)
BENIGN_DOMAINS = (
    "microsoft.com",
    "windowsupdate.com",
    "windows.com",
    "msftncsi.com",
    "digicert.com",
    "verisign.com",
    "symantec.com",
    "globalsign.com",
    "sectigo.com",
    "w3.org",
    "xmlsoap.org",
    "openxmlformats.org",
)
_PRIVATE = "private or reserved address"
_VENDOR = "well-known vendor domain"


@dataclass(frozen=True)
class Ioc:
    type: str
    value: str
    offsets: tuple[int, ...]
    benign_hint: str | None


def _hint(kind: str, value: str) -> str | None:
    if kind in ("ipv4", "ipv6"):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return None
        return _PRIVATE if not ip.is_global else None
    if kind == "domain":
        host = value.lower().rstrip(".")
        if any(host == d or host.endswith("." + d) for d in BENIGN_DOMAINS):
            return _VENDOR
    return None


def _url_host(url: str) -> str | None:
    """Host of ``url``; ``None`` when it does not parse (e.g. an unclosed ``[`` IPv6 bracket)."""
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def ioc_fact_id(ioc: Ioc) -> str:
    """Id of the ``ioc`` fact for ``ioc``: keyed by its lowest file offset.

    FLOSS-recovered strings have offset -1; they only count when nothing else is known,
    so an IOC seen in the file keeps its id (and its verdict) after FLOSS ran.
    """
    in_file = [o for o in ioc.offsets if o >= 0]
    return f"ioc:{ioc.type}:{hex(min(in_file or ioc.offsets))}"


def build_iocs(strings: Sequence[FoundString]) -> list[Ioc]:
    found: dict[tuple[str, str], list[int]] = {}

    def add(kind: str, value: str, offset: int) -> None:
        offsets = found.setdefault((kind, value), [])
        if offset not in offsets:
            offsets.append(offset)

    for s in strings:
        if s.category not in IOC_TYPES:
            continue
        add(s.category, s.value, s.offset)
        if s.category in ("url", "email"):
            host = _url_host(s.value) if s.category == "url" else s.value.split("@", 1)[1]
            if host:
                kind = "ipv4" if host.replace(".", "").isdigit() else "domain"
                add(kind, host, s.offset)
    return [
        Ioc(kind, value, tuple(sorted(offsets)), _hint(kind, value))
        for (kind, value), offsets in sorted(found.items(), key=lambda kv: min(kv[1]))
    ]


def iocs_csv(iocs: Sequence[Ioc]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["type", "value", "offsets", "benign_hint"])
    for i in iocs:
        writer.writerow([i.type, i.value, " ".join(hex(o) for o in i.offsets), i.benign_hint or ""])
    return buf.getvalue()


def iocs_json(iocs: Sequence[Ioc]) -> str:
    return json.dumps(
        [
            {
                "type": i.type,
                "value": i.value,
                "offsets": list(i.offsets),
                "benign_hint": i.benign_hint,
            }
            for i in iocs
        ],
        indent=2,
    )
