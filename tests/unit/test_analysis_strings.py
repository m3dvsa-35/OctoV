from __future__ import annotations

import pytest

from octov.core.analysis import strings as strings_mod
from octov.core.analysis.strings import FoundString, classify, extract_strings
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://x.example/gate.php", "url"),
        ("185.23.10.4", "ipv4"),
        ("1.2.3.4", None),
        ("FileVersion 1.2.3.4", None),
        ("kernel32.dll", None),
        ("evil-c2.top", "domain"),
        ("fe80::1ff:fe23:4567:890a", "ipv6"),
        ("admin@evil-c2.top", "email"),
        ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "registry"),
        ("C:\\Users\\Public\\a.exe", "path"),
        ("Global\\mtx_8812", "mutex"),
        ("Mozilla/5.0 (Windows NT 10.0)", "user_agent"),
        ("powershell -enc SQBFAFgA", "command"),
        ("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "wallet"),
        ("aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=", "base64"),
        ("Hello", None),
        ("GetProcAddress", None),
        ("Windows.System.Launcher", None),
        ("Windows.Storage.StorageFile", None),
        ("System.Net.WebClient", None),
    ],
)
def test_classify(value: str, expected: str | None) -> None:
    assert classify(value) == expected


def test_extract_ascii_and_utf16_with_offsets_and_rva() -> None:
    blob = (
        b"\x00" * 8
        + b"http://x.example/gate.php\x00"
        + "Global\\mtx_8812".encode("utf-16-le")
        + b"\x00\x00"
    )
    data = build_pe(
        PESpec(sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".data", blob, DATA)])
    )
    report = parse_pe(data)
    found = extract_strings(data, report)
    url = next(s for s in found if s.value == "http://x.example/gate.php")
    data_sec = report.sections[1]
    assert url.encoding == "ascii" and url.category == "url" and url.section == ".data"
    assert url.offset == data_sec.raw_offset + 8
    assert url.rva == data_sec.virtual_address + 8
    mutex = next(s for s in found if s.value == "Global\\mtx_8812")
    assert mutex.encoding == "utf16" and mutex.category == "mutex"
    assert [s.offset for s in found] == sorted(s.offset for s in found)


def test_extract_caps_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(strings_mod, "MAX_STRINGS", 5)
    data = b"\x00".join(b"word%04d" % i for i in range(50))
    assert len(extract_strings(data, None)) == 5


def test_raw_blob_strings_have_offsets_no_rva() -> None:
    found = extract_strings(b"\x00\x00http://raw.example/a\x00", None)
    assert [(s.value, s.offset, s.rva, s.section) for s in found] == [
        ("http://raw.example/a", 2, None, None)
    ]


def test_min_length_filters_short_runs() -> None:
    assert extract_strings(b"\x00abc\x00abcd\x00", None, min_len=4)[0].value == "abcd"


def test_found_string_defaults() -> None:
    s = FoundString("abcd", "ascii", 0, None, None, None)
    assert s.origin == "static" and s.function is None
