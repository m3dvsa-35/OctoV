from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
import yara
from sigma.collection import SigmaCollection

from octov.core.export.sigma_gen import generate_sigma
from octov.core.export.yara_gen import generate_yara
from octov.core.static.pe_parser import PEReport, parse_pe
from octov.core.static.rules import Finding, RuleEngine, load_rules
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

RULES = Path(__file__).resolve().parents[2] / "rules"


def _analysed(data: bytes) -> tuple[PEReport, list[Finding]]:
    report = parse_pe(data)
    engine = RuleEngine(load_rules([RULES / "evasion_patterns.yaml", RULES / "pic_patterns.yaml"]))
    return report, engine.scan(data, report)


@pytest.fixture(scope="module")
def suspicious() -> bytes:
    blob = (
        b"\x00" * 16
        + bytes.fromhex("4C8BD1B8180000000F05")
        + b"\x00" * 16
        + b'\\KnownDlls\\ntdll.dll "quoted"'
        + b"\x00" * 16
    )
    return build_pe(
        PESpec(
            sections=[
                SectionSpec(".text", b"\xc3" + b"\x90" * 15, TEXT),
                SectionSpec(".data", blob, DATA),
            ],
            imports={
                "kernel32.dll": [
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                    "VirtualProtect",
                    "MapViewOfFile",
                ]
            },
        )
    )


def test_yara_rule_compiles_and_matches_its_sample(suspicious: bytes) -> None:
    report, findings = _analysed(suspicious)
    assert {f.rule_id for f in findings} >= {"EVA-001", "EVA-007", "EVA-013"}
    source = generate_yara(report, findings)
    rules = yara.compile(source=source)
    assert rules.match(data=suspicious)
    assert not rules.match(data=build_pe())


def test_yara_rule_meta_and_name(suspicious: bytes) -> None:
    report, findings = _analysed(suspicious)
    source = generate_yara(report, findings)
    assert re.search(r"rule OctoV_[0-9a-f]{12}\b", source)
    assert f'sha256 = "{report.hashes.sha256}"' in source
    assert "T1055.001" in source and "EVA-001" in source


def test_yara_rule_custom_name_is_sanitised(suspicious: bytes) -> None:
    report, findings = _analysed(suspicious)
    source = generate_yara(report, findings, rule_name="IR case #42 / loader")
    assert "rule IR_case_42_loader" in source
    yara.compile(source=source)


def test_yara_falls_back_to_hash_rule_without_findings() -> None:
    data = build_pe(PESpec(imports={"kernel32.dll": ["ExitProcess"]}))
    report = parse_pe(data)
    rules = yara.compile(source=generate_yara(report, []))
    assert rules.match(data=data)
    assert not rules.match(data=data + b"\x00")


def test_sigma_rule_is_valid_and_carries_hashes(suspicious: bytes) -> None:
    report, findings = _analysed(suspicious)
    text = generate_sigma(report, findings)
    collection = SigmaCollection.from_yaml(text)
    assert len(collection.rules) == 1
    assert not collection.errors
    doc = yaml.safe_load(text)
    values = doc["detection"]["selection"]["Hashes|contains"]
    assert f"SHA256={report.hashes.sha256.upper()}" in values
    assert f"IMPHASH={report.hashes.imphash.upper()}" in values  # type: ignore[union-attr]
    assert doc["level"] == "high"
    assert "attack.t1055.001" in doc["tags"]
    assert doc["logsource"] == {"category": "process_creation", "product": "windows"}


def test_sigma_uses_image_load_for_dlls() -> None:
    data = build_pe(PESpec(is_dll=True, imports={"kernel32.dll": ["ExitProcess"]}))
    report, findings = _analysed(data)
    doc = yaml.safe_load(generate_sigma(report, findings))
    assert doc["logsource"]["category"] == "image_load"
    assert doc["level"] == "low"


def test_sigma_id_is_deterministic_per_sample(suspicious: bytes) -> None:
    report, findings = _analysed(suspicious)
    first = yaml.safe_load(generate_sigma(report, findings))["id"]
    assert first == yaml.safe_load(generate_sigma(report, findings))["id"]
