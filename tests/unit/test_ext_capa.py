from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from octov.core.static.cfg import BasicBlock, Function, FunctionIndex
from octov.core.static.disasm import Instruction
from octov.ext import capa_rules
from octov.ext.capa import (
    MEDIUM_PREFIXES,
    CapaMatch,
    capa_command,
    capa_facts,
    capa_severity,
    parse_capa,
)
from octov.ext.runner import EngineError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "capa"
BASE = 0x140000000


def _doc(name: str) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return doc


def test_fixtures_are_capa_10() -> None:
    for name in ("synthetic_injector.json", "notepad_trimmed.json"):
        assert _doc(name)["meta"]["version"].startswith("10.")


def test_command_shape(tmp_path: Path) -> None:
    cmd = capa_command(
        tmp_path / "s.exe", tmp_path / "rules", tmp_path / "sigs", raw=False, bits=64
    )
    assert cmd[:3] == [sys.executable, "-m", "capa.main"]
    assert "-j" in cmd and cmd[-1] == str(tmp_path / "s.exe")
    assert cmd[cmd.index("-r") + 1] == str(tmp_path / "rules")
    assert cmd[cmd.index("-s") + 1] == str(tmp_path / "sigs")
    raw = capa_command(tmp_path / "s.bin", tmp_path / "r", tmp_path / "s", raw=True, bits=32)
    assert raw[raw.index("-f") + 1] == "sc32"


def test_lib_rules_skipped() -> None:
    names = {m.rule for m in parse_capa(_doc("synthetic_injector.json"), BASE, 0x10000)}
    assert "write process memory" not in names  # lib rule
    assert {"create thread", "contain an embedded PE file"} <= names


def test_rvas_are_image_relative() -> None:
    matches = {m.rule: m for m in parse_capa(_doc("synthetic_injector.json"), BASE, 0x10000)}
    assert matches["create thread"].rvas == (0x1000,)
    assert matches["create thread"].namespace == "host-interaction/thread/create"
    assert matches["create thread"].mbc == ("C0038",)
    assert matches["contain an embedded PE file"].rvas == ()  # file scope: no address


def test_capa_addresses_outside_image_are_skipped() -> None:
    doc = copy.deepcopy(_doc("synthetic_injector.json"))
    doc["rules"]["create thread"]["matches"] = [
        [{"type": "absolute", "value": BASE - 0x10}, {"success": True}],
        [{"type": "absolute", "value": BASE + 0x20000}, {"success": True}],
        [{"type": "absolute", "value": BASE + 0x1004}, {"success": True}],
    ]
    matches = {m.rule: m for m in parse_capa(doc, BASE, 0x10000)}
    assert matches["create thread"].rvas == (0x1004,)


@pytest.mark.parametrize(
    ("namespace", "severity"),
    [
        # calibrated on System32 (2026-11-09): only C2 never matched a benign file
        ("communication/c2/command", "medium"),
        ("communication/c2/file-transfer", "medium"),
        ("host-interaction/process/inject", "info"),
        ("persistence/registry/run", "info"),
        ("anti-analysis/anti-vm/vm-detection", "info"),
        ("collection/keylog", "info"),
        ("anti-analysis/anti-debugging/debugger-detection", "info"),
        ("data-manipulation/encryption/aes", "info"),
        ("collection", "info"),
        ("", "info"),
    ],
)
def test_severity_mapping(namespace: str, severity: str) -> None:
    assert capa_severity(namespace) == severity


def test_medium_prefixes_after_calibration() -> None:
    assert MEDIUM_PREFIXES == ("communication/c2",)


def test_never_high_and_notepad_all_info() -> None:
    facts = capa_facts(parse_capa(_doc("notepad_trimmed.json"), BASE, 0x60000), None)
    assert facts and all(f.severity == "info" for f in facts)
    assert all(f.kind == "capability" for f in facts)


def test_unknown_schema_rejected() -> None:
    doc = copy.deepcopy(_doc("synthetic_injector.json"))
    doc["meta"]["version"] = "9.3.0"
    with pytest.raises(EngineError) as err:
        parse_capa(doc, BASE, 0x10000)
    assert err.value.kind == "bad_output"
    with pytest.raises(EngineError):
        parse_capa({"meta": {}}, BASE, 0x10000)


def test_facts_attach_to_containing_function() -> None:
    insn = Instruction(0x1000, 0x40, "nop", "", bytes([0x90]) * 0x40)
    index = FunctionIndex({0x1000: Function(0x1000, {0x1000: BasicBlock(0x1000, [insn])}, [])})
    match = CapaMatch("receive data", "communication/c2/command", ("T1071",), (), (0x1010,))
    fact = capa_facts([match], index)[0]
    assert fact.severity == "medium"
    assert fact.evidence[0].rva == 0x1000
    assert 0x1010 in [e.rva for e in fact.evidence]
    assert fact.mitre == ("T1071",)
    assert "communication/c2/command" in fact.tags
    assert fact.explain_key == "capa.ns.communication"


def test_match_without_address_has_value_evidence() -> None:
    fact = capa_facts(
        [CapaMatch("contain an embedded PE file", "executable/subfile/pe", (), (), ())], None
    )[0]
    # file-scope matches anchor at the file start (every fact needs an offset or RVA)
    assert len(fact.evidence) == 1
    assert (fact.evidence[0].offset, fact.evidence[0].rva) == (0, 0)


def test_sigs_install_from_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src"
    src.mkdir()
    pins = {}
    for name in capa_rules.CAPA_SIGS:
        (src / name).write_bytes(name.encode())
        pins[name] = hashlib.sha256(name.encode()).hexdigest()
    monkeypatch.setattr(capa_rules, "CAPA_SIGS", pins)
    target = capa_rules.install_sigs(tmp_path / "sigs", from_dir=src)
    assert target == tmp_path / "sigs" / capa_rules.CAPA_RULES_VERSION
    assert sorted(p.name for p in target.iterdir()) == sorted(pins)


def test_sigs_checksum_mismatch(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    for name in capa_rules.CAPA_SIGS:
        (src / name).write_bytes(b"wrong")
    with pytest.raises(capa_rules.RulesError, match="checksum mismatch"):
        capa_rules.install_sigs(tmp_path / "sigs", from_dir=src)


def _capa_ready() -> tuple[Path, Path] | None:
    from octov.ext import DEFAULT_RULES_ROOT, DEFAULT_SIGS_ROOT, capa_rules_dir, extension_status

    root = DEFAULT_RULES_ROOT.expanduser()
    if not next(s for s in extension_status(root) if s.id == "capa").ready:
        return None
    rules = capa_rules_dir(root)
    assert rules is not None
    sigs = DEFAULT_SIGS_ROOT.expanduser() / rules[0]
    return (rules[1], sigs) if sigs.is_dir() else None


@pytest.mark.skipif(_capa_ready() is None, reason="capa, its rules and signatures not installed")
def test_integration_real_capa_on_synthetic_injector(tmp_path: Path) -> None:
    import threading

    from octov.ext.runner import parse_json, run_engine
    from tests.unit.test_triage_api import _suspicious

    ready = _capa_ready()
    assert ready is not None
    sample = _suspicious(tmp_path)
    run = run_engine(
        capa_command(sample, ready[0], ready[1], raw=False, bits=64),
        timeout_s=300,
        max_memory_mb=4096,
        cancel=threading.Event(),
    )
    names = {m.rule for m in parse_capa(parse_json(run), BASE, 0x10000)}
    assert "create thread" in names
