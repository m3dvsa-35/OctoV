"""Raw (non-PE) input mode: shellcode-style blobs analysed without a PE header.

The blobs here are inert byte sequences that merely *contain* the patterns the
PIC rules look for; they are never executed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yara

from octov.cli.main import main
from octov.core.export.yara_gen import generate_yara
from octov.core.static.analysis import analyze_raw
from octov.core.static.cfg import discover_from
from octov.core.static.disasm import Disassembler, RawView

# x64: call $+5 / pop rax (GetPC) ... gs:[0x60] PEB read ... ret
PIC_X64 = (
    bytes.fromhex("E80000000058") + b"\x90" * 4 + bytes.fromhex("65488B042560000000") + b"\xc3"
)
# test rcx,rcx / je L1 / mov eax,1 / ret / L1: xor eax,eax / call helper / ret / pad / helper: ret
BRANCHY = bytes.fromhex("4885C97406B801000000C331C0E80E000000C3") + b"\xcc" * 13 + b"\xc3"


def test_raw_analysis_finds_pic_patterns_with_offsets() -> None:
    result = analyze_raw(PIC_X64)
    ids = {f.rule_id for f in result.findings}
    assert {"PIC-001", "PIC-003"} <= ids
    getpc = next(f for f in result.findings if f.rule_id == "PIC-003")
    assert getpc.matches[0].offset == 0
    assert result.sample.hashes.sha256 == hashlib.sha256(PIC_X64).hexdigest()
    assert result.sample.hashes.imphash is None


def test_raw_analysis_ignores_pe_only_indicators() -> None:
    # Import/section indicators need a PE; a blob merely containing the names must not match.
    result = analyze_raw(b"VirtualAllocEx WriteProcessMemory CreateRemoteThread")
    assert "EVA-007" not in {f.rule_id for f in result.findings}


def test_raw_disassembly_and_function_discovery_x64() -> None:
    dis = Disassembler(RawView(BRANCHY, bits=64))
    assert [i.mnemonic for i in dis.linear(0, 3)] == ["test", "je", "mov"]
    functions = discover_from(dis, [0])
    assert set(functions) == {0, 0x20}
    assert sorted(functions[0].blocks) == [0, 5, 0xB]


def test_raw_disassembly_x86_mode() -> None:
    dis = Disassembler(RawView(bytes.fromhex("E80000000058C3"), bits=32))
    assert [i.text() for i in dis.linear(0, 3)] == ["call 5", "pop eax", "ret"]


def test_raw_view_reads_inside_blob_only() -> None:
    view = RawView(b"\x90\xc3", bits=64)
    assert view.read(0, 10) == b"\x90\xc3"
    assert view.read(5, 4) == b""
    assert view.is_executable(1) and not view.is_executable(2)


def test_yara_for_raw_blob_has_no_pe_anchor() -> None:
    result = analyze_raw(PIC_X64)
    source = generate_yara(result.sample, result.findings)
    assert "0x5A4D" not in source and 'import "pe"' in source
    rules = yara.compile(source=source)
    assert rules.match(data=b"\x00" * 64 + PIC_X64)
    assert not rules.match(data=BRANCHY)


def test_raw_to_dict_is_tagged() -> None:
    d = analyze_raw(PIC_X64).to_dict()
    assert d["format"] == "raw" and d["bits"] == 64
    assert d["hashes"]["sha256"] == hashlib.sha256(PIC_X64).hexdigest()


# --- CLI --------------------------------------------------------------------------


def _blob(tmp_path: Path) -> Path:
    path = tmp_path / "blob.bin"
    path.write_bytes(PIC_X64)
    return path


def test_cli_raw_mode_reports_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(_blob(tmp_path)), "--raw"]) == 0
    out = capsys.readouterr().out
    assert "raw x64" in out and "PIC-003" in out and "@ off 0x0" in out


def test_cli_raw_json_and_yara(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    yar = tmp_path / "blob.yar"
    assert main(["analyze", str(_blob(tmp_path)), "--raw", "--json", "--yara", str(yar)]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "raw"
    assert yara.compile(filepath=str(yar)).match(str(_blob(tmp_path)))


def test_cli_raw_rejects_sigma(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "x.yml"
    assert main(["analyze", str(_blob(tmp_path)), "--raw", "--sigma", str(out)]) == 2
    assert "sigma" in capsys.readouterr().err.lower()
    assert not out.exists()


def test_cli_non_pe_without_raw_suggests_raw(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["analyze", str(_blob(tmp_path))]) == 2
    assert "--raw" in capsys.readouterr().err
