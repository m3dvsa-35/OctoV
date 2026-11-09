from __future__ import annotations

import os
from pathlib import Path

import pytest

from octov.core.analysis.naming import API_FAMILIES, suggest_name, suggest_name_from_capa
from octov.core.analysis.packer import packer_fact, packer_verdict
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import RWX, TEXT, PESpec, SectionSpec, build_pe


def _upx_like() -> bytes:
    return build_pe(
        PESpec(
            sections=[
                SectionSpec("UPX0", b"", RWX, virtual_size=0x10000),
                SectionSpec("UPX1", os.urandom(8192), RWX),
            ],
            entry_section=1,
            imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]},
        )
    )


def test_upx_like_sample_is_packed() -> None:
    verdict = packer_verdict(parse_pe(_upx_like()))
    assert verdict.packed and verdict.packer == "UPX"
    assert len(verdict.reasons) >= 2 and 0 < verdict.confidence <= 1


def test_normal_sample_is_not_packed() -> None:
    data = build_pe(
        PESpec(
            sections=[SectionSpec(".text", b"\xc3" + b"\x90" * 64, TEXT)],
            imports={"kernel32.dll": ["ExitProcess", "GetStdHandle", "WriteFile", "CloseHandle"]},
        )
    )
    verdict = packer_verdict(parse_pe(data))
    assert not verdict.packed
    assert packer_fact(parse_pe(data), verdict) is None


def test_packer_fact_points_at_entry() -> None:
    report = parse_pe(_upx_like())
    fact = packer_fact(report, packer_verdict(report))
    assert fact is not None and fact.kind == "packer" and fact.severity == "medium"
    assert fact.evidence[0].rva == report.entry_point


NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


@pytest.mark.skipif(not NOTEPAD.exists(), reason="Windows system binary not available")
def test_notepad_is_not_packed() -> None:
    assert not packer_verdict(parse_pe(NOTEPAD.read_bytes())).packed


def test_families_present() -> None:
    assert {
        "net_http",
        "net_socket",
        "file_io",
        "registry",
        "process",
        "thread_inject",
        "crypto",
        "service",
        "mutex",
        "anti_debug",
    } <= set(API_FAMILIES)


def test_suggest_name_dominant_family() -> None:
    calls = ["wininet.dll!InternetOpenA", "wininet.dll!HttpSendRequestA", "kernel32.dll!Sleep"]
    assert suggest_name(0x401000, calls) == "net_http_401000"


def test_suggest_name_ignores_ansi_unicode_suffix() -> None:
    calls = ["advapi32.dll!RegOpenKeyExW", "advapi32.dll!RegSetValueExW"]
    assert suggest_name(0x1000, calls) == "registry_1000"


def test_suggest_name_needs_two_calls_and_majority() -> None:
    assert suggest_name(0x1000, ["wininet.dll!InternetOpenA"]) is None
    mixed = [
        "wininet.dll!InternetOpenA",
        "wininet.dll!HttpSendRequestA",
        "advapi32.dll!RegOpenKeyExW",
        "advapi32.dll!RegSetValueExW",
    ]
    assert suggest_name(0x1000, mixed) is None


def test_capa_name_single_medium() -> None:
    rules = [("inject thread", "medium"), ("contain loop", "info")]
    assert suggest_name_from_capa(0x1000, rules) == "inject_thread_1000"


def test_capa_name_two_medium_is_none() -> None:
    assert suggest_name_from_capa(0x1000, [("a", "medium"), ("b", "medium")]) is None
    assert suggest_name_from_capa(0x1000, [("contain loop", "info")]) is None


def test_capa_name_slug_is_short_and_safe() -> None:
    name = suggest_name_from_capa(
        0x2000, [("Write Process Memory (via NtWrite...) / v2", "medium")]
    )
    assert name is not None and name.endswith("_2000")
    stem = name[: -len("_2000")]
    assert len(stem) <= 32 and stem.replace("_", "").isalnum() and stem == stem.lower()
