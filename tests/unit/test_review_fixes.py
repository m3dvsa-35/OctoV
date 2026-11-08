"""Regression tests for the M2 code-review findings."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from octov.cli.main import main
from octov.core.static.disasm import Disassembler, ImageView
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

BRANCHY = bytes.fromhex("4885C97406B801000000C331C0E80E000000C3") + b"\xcc" * 13 + b"\xc3"
STUB = bytes.fromhex("4C8BD1B8180000000F05")


def _sample(tag: bytes = b"") -> bytes:
    return build_pe(
        PESpec(
            sections=[
                SectionSpec(".text", BRANCHY, TEXT),
                SectionSpec(".data", b"\x00" * 32 + STUB + b"\x00" * 8 + tag, DATA),
            ],
            imports={"kernel32.dll": ["ExitProcess"]},
        )
    )


def _custom_rules(tmp_path: Path) -> Path:
    path = tmp_path / "custom.yaml"
    rule = {
        "id": "CUST-1",
        "name": "custom marker",
        "description": "test marker string",
        "severity": "low",
        "mitre": ["T1027"],
        "condition": "any",
        "indicators": [{"type": "string", "value": "octov-test-marker"}],
    }
    path.write_text(yaml.safe_dump({"version": 1, "rules": [rule]}), encoding="utf-8")
    return path


def test_cli_uses_rule_paths_from_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    custom = _custom_rules(tmp_path)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"rules:\n  paths: [{custom.name}]\n", encoding="utf-8")
    sample = tmp_path / "m.exe"
    sample.write_bytes(_sample(b"octov-test-marker"))
    assert main(["analyze", str(sample), "--config", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert "CUST-1" in out
    assert "EVA-001" not in out  # catalog list replaced by config


def test_cli_rejects_duplicate_rule_ids(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dup = tmp_path / "dup.yaml"
    rule = {
        "id": "EVA-001",
        "name": "dup",
        "description": "d",
        "severity": "low",
        "mitre": ["T1106"],
        "indicators": [{"type": "string", "value": "x"}],
    }
    dup.write_text(yaml.safe_dump({"version": 1, "rules": [rule]}), encoding="utf-8")
    sample = tmp_path / "m.exe"
    sample.write_bytes(_sample())
    assert main(["analyze", str(sample), "--rules", str(dup)]) == 2
    assert "duplicate" in capsys.readouterr().err


def _dis() -> Disassembler:
    data = _sample()
    return Disassembler(ImageView(data, parse_pe(data)))


def test_far_jump_and_call_are_branches() -> None:
    dis = _dis()
    ljmp = dis._convert(0x1000, 7, "ljmp", "0x33:0x1010", b"")
    lcall = dis._convert(0x1000, 7, "lcall", "0x33:0x1010", b"")
    assert ljmp.is_jump and not ljmp.is_conditional and ljmp.target is None
    assert lcall.is_call


def test_decimal_branch_targets_are_parsed() -> None:
    dis = _dis()
    assert dis._convert(0, 2, "jmp", "5", b"").target == 5
    assert dis._convert(0, 2, "jmp", "rax", b"").target is None
