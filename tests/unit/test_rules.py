from __future__ import annotations

from pathlib import Path

import pytest

from octov.core.static.pe_parser import parse_pe
from octov.core.static.rules import (
    Rule,
    RuleEngine,
    RuleError,
    compile_pattern,
    load_rules,
    required_matches,
)
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe
from tests.samples.corpus import sample_for_rule

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
CATALOGS = [RULES_DIR / "evasion_patterns.yaml", RULES_DIR / "pic_patterns.yaml"]


def _rule(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "T-1",
        "name": "test",
        "description": "d",
        "severity": "medium",
        "mitre": ["T1055"],
        "condition": "any",
        "indicators": [{"type": "string", "value": "needle"}],
    }
    base.update(overrides)
    return base


def _write_rules(tmp_path: Path, *rules: dict[str, object]) -> Path:
    import yaml

    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "rules": list(rules)}), encoding="utf-8")
    return path


# --- byte patterns ------------------------------------------------------------


def test_pattern_with_full_byte_wildcards() -> None:
    pat = compile_pattern("4C 8B ?? 0F")
    assert pat.search(b"\x00\x4c\x8b\x99\x0f") is not None
    assert pat.search(b"\x4c\x8b\x99\x0e") is None


def test_pattern_with_nibble_wildcards() -> None:
    hi = compile_pattern("E8 00 00 00 00 5?")
    assert hi.search(b"\xe8\x00\x00\x00\x00\x58")
    assert not hi.search(b"\xe8\x00\x00\x00\x00\x68")
    lo = compile_pattern("?5")
    assert lo.search(b"\x75") and not lo.search(b"\x76")


def test_pattern_matches_newline_bytes() -> None:
    assert compile_pattern("0A ?? 0A").search(b"\x0a\x0a\x0a")


@pytest.mark.parametrize("bad", ["", "4", "ZZ", "4C8B", "4C  ?"])
def test_invalid_patterns_rejected(bad: str) -> None:
    with pytest.raises(RuleError):
        compile_pattern(bad)


# --- loading ------------------------------------------------------------------


def test_loads_shipped_catalogs() -> None:
    rules = load_rules(CATALOGS)
    assert len(rules) >= 30
    assert len({r.id for r in rules}) == len(rules)


@pytest.mark.parametrize(
    "override",
    [
        {"severity": "critical"},
        {"condition": "most"},
        {"condition": 5},
        {"indicators": []},
        {"indicators": [{"type": "regex", "value": "x"}]},
        {"mitre": ["X1"]},
    ],
)
def test_invalid_rule_rejected(tmp_path: Path, override: dict[str, object]) -> None:
    with pytest.raises(RuleError):
        load_rules([_write_rules(tmp_path, _rule(**override))])


def test_duplicate_ids_rejected(tmp_path: Path) -> None:
    with pytest.raises(RuleError):
        load_rules([_write_rules(tmp_path, _rule(), _rule())])


def test_required_matches() -> None:
    assert required_matches("any", 4) == 1
    assert required_matches("all", 4) == 4
    assert required_matches(2, 4) == 2


# --- matching -----------------------------------------------------------------


def _engine(tmp_path: Path, *rules: dict[str, object]) -> RuleEngine:
    return RuleEngine(load_rules([_write_rules(tmp_path, *rules)]))


def test_bytes_match_reports_file_offset_and_rva(tmp_path: Path) -> None:
    code = b"\x90" * 0x20 + bytes.fromhex("4C8BD1B83F0000000F05") + b"\xc3"
    data = build_pe(PESpec(sections=[SectionSpec(".text", code, TEXT)]))
    report = parse_pe(data)
    engine = _engine(
        tmp_path, _rule(indicators=[{"type": "bytes", "value": "4C 8B D1 B8 ?? ?? 00 00 0F 05"}])
    )
    [finding] = engine.scan(data, report)
    [match] = finding.matches
    text = report.sections[0]
    assert match.offset == text.raw_offset + 0x20
    assert match.rva == text.virtual_address + 0x20


def test_string_matches_ascii_and_utf16(tmp_path: Path) -> None:
    engine = _engine(tmp_path, _rule(indicators=[{"type": "string", "value": "AmsiScanBuffer"}]))
    assert engine.scan(b"xx AmsiScanBuffer yy")
    assert engine.scan("..AmsiScanBuffer..".encode("utf-16-le"))
    assert not engine.scan(b"amsiscanbuffer")


def test_import_indicator_ignores_ansi_unicode_suffix(tmp_path: Path) -> None:
    data = build_pe(PESpec(imports={"kernel32.dll": ["CreateProcessW", "ExitProcess"]}))
    engine = _engine(tmp_path, _rule(indicators=[{"type": "import", "value": "CreateProcess"}]))
    [finding] = engine.scan(data, parse_pe(data))
    assert finding.matches[0].detail == "kernel32.dll!CreateProcessW"


def test_import_indicators_need_a_pe_report(tmp_path: Path) -> None:
    engine = _engine(tmp_path, _rule(indicators=[{"type": "import", "value": "CreateProcess"}]))
    assert engine.scan(b"CreateProcessW") == []


def test_condition_all_and_threshold(tmp_path: Path) -> None:
    inds = [{"type": "string", "value": v} for v in ("alpha", "bravo", "charlie")]
    all_engine = _engine(tmp_path, _rule(condition="all", indicators=inds))
    two_engine = _engine(tmp_path, _rule(condition=2, indicators=inds))
    assert all_engine.scan(b"alpha bravo") == []
    assert two_engine.scan(b"alpha bravo")
    assert two_engine.scan(b"alpha") == []
    assert all_engine.scan(b"alpha bravo charlie")


def test_section_indicator(tmp_path: Path) -> None:
    data = build_pe(
        PESpec(sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".vmp0", b"x", DATA)])
    )
    engine = _engine(tmp_path, _rule(indicators=[{"type": "section", "value": ".vmp0"}]))
    assert engine.scan(data, parse_pe(data))


def test_unless_suppresses_rule(tmp_path: Path) -> None:
    rule = _rule(
        indicators=[{"type": "string", "value": "needle"}],
        unless=[{"type": "string", "value": "benign-context"}],
    )
    engine = _engine(tmp_path, rule)
    assert engine.scan(b"needle")
    assert engine.scan(b"needle benign-context") == []


def test_finding_carries_rule_metadata(tmp_path: Path) -> None:
    [finding] = _engine(tmp_path, _rule()).scan(b"a needle")
    assert (finding.rule_id, finding.severity, finding.mitre) == ("T-1", "medium", ["T1055"])
    assert finding.to_dict()["matches"][0]["offset"] == 2


# --- shipped catalog corpus: every rule must detect its own synthetic sample ---

_ALL_RULES = load_rules(CATALOGS)


@pytest.mark.parametrize("rule", _ALL_RULES, ids=lambda r: r.id)
def test_catalog_rule_detects_synthetic_sample(rule: Rule) -> None:
    data = sample_for_rule(rule)
    found = {f.rule_id for f in RuleEngine([rule]).scan(data, parse_pe(data))}
    assert rule.id in found


@pytest.mark.parametrize(
    "rule",
    [r for r in _ALL_RULES if required_matches(r.condition, len(r.indicators)) > 1],
    ids=lambda r: r.id,
)
def test_catalog_rule_respects_threshold(rule: Rule) -> None:
    data = sample_for_rule(rule, below_threshold=True)
    assert RuleEngine([rule]).scan(data, parse_pe(data)) == []


def test_module_exporting_an_api_does_not_count_as_using_it(tmp_path: Path) -> None:
    # Builder has no export table; emulate an API provider by patching the parsed report.
    data = build_pe(PESpec(imports={"kernel32.dll": ["VirtualAllocEx"]}))
    report = parse_pe(data)
    engine = _engine(
        tmp_path,
        _rule(
            indicators=[
                {"type": "import", "value": "VirtualAllocEx"},
                {"type": "string", "value": "VirtualAllocEx"},
            ]
        ),
    )
    assert engine.scan(data, report)
    report.exports = ["VirtualAllocEx"]
    assert engine.scan(data, report) == []


def test_parse_and_rules_on_10mb_pe_under_two_seconds() -> None:
    import os
    import time

    from octov.core.static.analysis import analyze

    blob = os.urandom(10 * 1024 * 1024)
    data = build_pe(
        PESpec(
            sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".rsrc", blob, DATA)],
            imports={"kernel32.dll": ["ExitProcess"]},
        )
    )
    analyze(build_pe())  # load + compile catalogs once
    start = time.perf_counter()
    analyze(data)
    assert time.perf_counter() - start < 2.0
