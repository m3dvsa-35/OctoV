from __future__ import annotations

import hashlib
import os
import random
import time
from pathlib import Path

import msgpack
import pytest

from octov.core.static.pe_parser import PEParseError, parse_pe, shannon_entropy
from tests.samples.builder import DATA, RWX, TEXT, PESpec, SectionSpec, build_pe


def _write(tmp_path: Path, spec: PESpec | None = None, name: str = "sample.exe") -> Path:
    path = tmp_path / name
    path.write_bytes(build_pe(spec))
    return path


def _ids(report: object) -> set[str]:
    return {i.id for i in report.indicators}  # type: ignore[attr-defined]


# --- entropy ----------------------------------------------------------------


def test_entropy_of_empty_and_constant_data_is_zero() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 4096) == 0.0


def test_entropy_of_uniform_bytes_is_eight() -> None:
    assert shannon_entropy(bytes(range(256)) * 16) == pytest.approx(8.0)


# --- basic header facts -----------------------------------------------------


def test_parses_basic_header_fields(tmp_path: Path) -> None:
    path = _write(tmp_path)
    report = parse_pe(path)

    assert report.is_64bit is True
    assert report.is_dll is False
    assert report.machine == "AMD64"
    assert report.entry_point == 0x1000
    assert report.image_base == 0x140000000
    assert report.subsystem == "WINDOWS_CUI"
    assert [s.name for s in report.sections] == [".text"]


def test_hashes_match_file_content(tmp_path: Path) -> None:
    path = _write(tmp_path)
    data = path.read_bytes()
    report = parse_pe(path)

    assert report.hashes.sha256 == hashlib.sha256(data).hexdigest()
    assert report.hashes.md5 == hashlib.md5(data).hexdigest()
    assert report.hashes.sha1 == hashlib.sha1(data).hexdigest()
    assert report.size == len(data)


def test_accepts_raw_bytes(tmp_path: Path) -> None:
    data = build_pe()
    report = parse_pe(data)
    assert report.hashes.sha256 == hashlib.sha256(data).hexdigest()
    assert report.path is None


def test_detects_dll_flag(tmp_path: Path) -> None:
    report = parse_pe(_write(tmp_path, PESpec(is_dll=True), "lib.dll"))
    assert report.is_dll is True


def test_section_permissions(tmp_path: Path) -> None:
    spec = PESpec(sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".data", b"x", DATA)])
    text, data = parse_pe(_write(tmp_path, spec)).sections
    assert (text.readable, text.writable, text.executable) == (True, False, True)
    assert (data.readable, data.writable, data.executable) == (True, True, False)


def test_parses_imports_and_imphash(tmp_path: Path) -> None:
    spec = PESpec(
        imports={"KERNEL32.dll": ["ExitProcess", "GetStdHandle"], "user32.dll": ["MessageBoxA"]}
    )
    report = parse_pe(_write(tmp_path, spec))
    assert report.imports == {
        "kernel32.dll": ["ExitProcess", "GetStdHandle"],
        "user32.dll": ["MessageBoxA"],
    }
    assert report.hashes.imphash and len(report.hashes.imphash) == 32


def test_invalid_file_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"MZ not really a pe" * 10)
    with pytest.raises(PEParseError):
        parse_pe(bad)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PEParseError):
        parse_pe(tmp_path / "nope.exe")


# --- packing / evasion indicators ------------------------------------------


def test_benign_sample_has_no_high_severity_indicators(tmp_path: Path) -> None:
    spec = PESpec(
        imports={
            "kernel32.dll": [
                "ExitProcess",
                "GetStdHandle",
                "WriteFile",
                "CloseHandle",
                "GetLastError",
                "HeapAlloc",
            ]
        }
    )
    report = parse_pe(_write(tmp_path, spec))
    assert [i for i in report.indicators if i.severity == "high"] == []


def test_flags_high_entropy_section(tmp_path: Path) -> None:
    rng = random.Random(1337)
    blob = bytes(rng.getrandbits(8) for _ in range(64 * 1024))
    spec = PESpec(sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".rsrc", blob, DATA)])
    report = parse_pe(_write(tmp_path, spec))
    assert "high_entropy_section" in _ids(report)
    rsrc = report.sections[1]
    assert rsrc.entropy > 7.5


def test_flags_rwx_section(tmp_path: Path) -> None:
    spec = PESpec(sections=[SectionSpec(".text", b"\xc3", RWX)])
    report = parse_pe(_write(tmp_path, spec))
    ind = next(i for i in report.indicators if i.id == "rwx_section")
    assert ind.evidence["section"] == ".text"


def test_flags_known_packer_section_names(tmp_path: Path) -> None:
    spec = PESpec(
        sections=[
            SectionSpec("UPX0", b"", RWX, virtual_size=0x8000),
            SectionSpec("UPX1", b"\xc3" * 64, RWX),
        ],
        entry_section=1,
    )
    ids = _ids(parse_pe(_write(tmp_path, spec)))
    assert "packer_section_name" in ids
    assert "virtual_size_inflated" in ids


def test_flags_entry_point_in_non_executable_section(tmp_path: Path) -> None:
    spec = PESpec(
        sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".data", b"\xc3", DATA)],
        entry_section=1,
    )
    assert "entry_point_not_executable" in _ids(parse_pe(_write(tmp_path, spec)))


def test_flags_minimal_imports_with_dynamic_resolution(tmp_path: Path) -> None:
    spec = PESpec(imports={"kernel32.dll": ["LoadLibraryA", "GetProcAddress"]})
    ind = next(
        i for i in parse_pe(_write(tmp_path, spec)).indicators if i.id == "dynamic_api_resolution"
    )
    assert "T1027.007" in ind.mitre


def test_flags_process_injection_apis_with_mitre(tmp_path: Path) -> None:
    spec = PESpec(
        imports={
            "kernel32.dll": [
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "ExitProcess",
            ]
        }
    )
    ind = next(
        i for i in parse_pe(_write(tmp_path, spec)).indicators if i.id == "process_injection_apis"
    )
    assert ind.severity == "medium"  # capability via dual-use APIs, not intent
    assert "T1055" in ind.mitre
    assert set(ind.evidence["apis"]) >= {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    }


def test_detects_overlay(tmp_path: Path) -> None:
    report = parse_pe(_write(tmp_path, PESpec(overlay=os.urandom(4096))))
    assert report.overlay_size == 4096
    assert "overlay_present" in _ids(report)


# --- serialisation & performance -------------------------------------------


def test_report_roundtrips_through_msgpack(tmp_path: Path) -> None:
    spec = PESpec(imports={"kernel32.dll": ["WriteProcessMemory", "CreateRemoteThread"]})
    report = parse_pe(_write(tmp_path, spec))
    restored = msgpack.unpackb(msgpack.packb(report.to_dict()))
    assert restored["hashes"]["sha256"] == report.hashes.sha256
    assert restored["sections"][0]["name"] == ".text"
    assert restored["indicators"]


def test_parses_10mb_pe_under_two_seconds(tmp_path: Path) -> None:
    blob = os.urandom(10 * 1024 * 1024)
    spec = PESpec(
        sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".rsrc", blob, DATA)],
        imports={"kernel32.dll": ["ExitProcess"]},
    )
    path = _write(tmp_path, spec)
    start = time.perf_counter()
    parse_pe(path)
    assert time.perf_counter() - start < 2.0


def test_unsigned_sample_reports_no_signature(tmp_path: Path) -> None:
    report = parse_pe(_write(tmp_path))
    assert report.signature.present is False
    assert report.signature.verified is None
