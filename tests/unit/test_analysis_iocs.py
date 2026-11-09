from __future__ import annotations

import csv
import io
import json

from octov.core.analysis.iocs import build_iocs, iocs_csv, iocs_json
from octov.core.analysis.strings import FoundString, classify


def _s(value: str, offset: int) -> FoundString:
    return FoundString(value, "ascii", offset, None, None, classify(value))


def test_dedupes_values_and_keeps_all_offsets() -> None:
    iocs = build_iocs([_s("http://x.example/gate.php", 10), _s("http://x.example/gate.php", 90)])
    url = next(i for i in iocs if i.type == "url")
    assert url.offsets == (10, 90)


def test_domain_from_url_is_listed() -> None:
    iocs = build_iocs([_s("http://x.example/gate.php", 10)])
    assert ("domain", "x.example") in {(i.type, i.value) for i in iocs}


def test_private_and_reserved_addresses_are_flagged() -> None:
    iocs = {
        i.value: i
        for i in build_iocs(
            [
                _s(v, n)
                for n, v in enumerate(["10.0.0.5", "127.0.0.1", "192.168.1.1", "185.23.10.4"])
            ]
        )
    }
    assert iocs["10.0.0.5"].benign_hint == "private or reserved address"
    assert iocs["127.0.0.1"].benign_hint == "private or reserved address"
    assert iocs["192.168.1.1"].benign_hint == "private or reserved address"
    assert iocs["185.23.10.4"].benign_hint is None


def test_vendor_domains_are_flagged() -> None:
    iocs = {
        i.value: i
        for i in build_iocs(
            [_s("http://go.microsoft.com/fwlink", 1), _s("update.windowsupdate.com", 2)]
        )
    }
    assert iocs["go.microsoft.com"].benign_hint == "well-known vendor domain"
    assert iocs["update.windowsupdate.com"].benign_hint == "well-known vendor domain"


def test_non_ioc_categories_are_ignored() -> None:
    assert build_iocs([_s("aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=", 1), _s("Hello world", 2)]) == []


def test_csv_and_json_exports() -> None:
    iocs = build_iocs([_s("C:\\a,b\\x.exe", 4), _s("evil-c2.top", 8)])
    rows = list(csv.reader(io.StringIO(iocs_csv(iocs))))
    assert rows[0] == ["type", "value", "offsets", "benign_hint"]
    assert ["path", "C:\\a,b\\x.exe", "0x4", ""] in rows
    data = json.loads(iocs_json(iocs))
    assert {"type": "domain", "value": "evil-c2.top", "offsets": [8], "benign_hint": None} in data
