from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from octov.cli.main import main
from octov.core.session.session import Session
from tests.samples.builder import PESpec, build_pe

RULES = Path(__file__).resolve().parents[2] / "rules"
MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def _sample(tmp_path: Path) -> Path:
    path = tmp_path / "s.exe"
    path.write_bytes(
        build_pe(PESpec(imports={"kernel32.dll": ["WriteProcessMemory", "CreateRemoteThread"]}))
    )
    return path


def test_analyze_json_outputs_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(_sample(tmp_path)), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out["hashes"]["sha256"]) == 64
    assert any(i["id"] == "process_injection_apis" for i in out["indicators"])


def test_analyze_text_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(_sample(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "process_injection_apis" in out
    assert "T1055" in out


def test_analyze_stores_into_session(tmp_path: Path) -> None:
    session_path = tmp_path / "case.octov"
    assert main(["analyze", str(_sample(tmp_path)), "--session", str(session_path)]) == 0
    with Session.open(session_path) as s:
        assert len(s.list_samples()) == 1


def test_analyze_invalid_file_returns_error_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"xx")
    assert main(["analyze", str(bad)]) == 2
    assert "error" in capsys.readouterr().err.lower()


@pytest.mark.parametrize("name", ["evasion_patterns.yaml", "pic_patterns.yaml"])
def test_rule_catalogs_are_well_formed(name: str) -> None:
    doc = yaml.safe_load((RULES / name).read_text(encoding="utf-8"))
    rules = doc["rules"]
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for rule in rules:
        assert {"id", "name", "description", "severity", "mitre", "indicators"} <= set(rule), rule[
            "id"
        ]
        assert rule["severity"] in {"info", "low", "medium", "high"}
        assert rule["mitre"] and all(MITRE_ID.match(m) for m in rule["mitre"]), rule["id"]
        for ind in rule["indicators"]:
            assert ind["type"] in {"import", "string", "bytes", "section"}, rule["id"]
            if ind["type"] == "bytes":
                assert re.fullmatch(r"([0-9A-F?]{2} ?)+", ind["value"]), rule["id"]


def test_evasion_catalog_covers_twenty_techniques() -> None:
    doc = yaml.safe_load((RULES / "evasion_patterns.yaml").read_text(encoding="utf-8"))
    assert len(doc["rules"]) >= 20


def _evasive(tmp_path: Path) -> Path:
    from tests.samples.builder import DATA, TEXT, SectionSpec

    blob = b"\x00" * 16 + bytes.fromhex("4C8BD1B8180000000F05") + b"\x00" * 16
    path = tmp_path / "ev.exe"
    path.write_bytes(
        build_pe(
            PESpec(
                sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".data", blob, DATA)],
                imports={"kernel32.dll": ["ExitProcess"]},
            )
        )
    )
    return path


def test_analyze_reports_rule_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(_evasive(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "EVA-001" in out and "Direct system call stub" in out


def test_analyze_json_contains_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(_evasive(tmp_path)), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    [finding] = [f for f in out["findings"] if f["rule_id"] == "EVA-001"]
    assert finding["matches"][0]["rva"] is not None


def test_analyze_writes_yara_and_sigma(tmp_path: Path) -> None:
    import yara

    sample = _evasive(tmp_path)
    yar, sig = tmp_path / "out.yar", tmp_path / "out.yml"
    assert main(["analyze", str(sample), "--yara", str(yar), "--sigma", str(sig)]) == 0
    assert yara.compile(filepath=str(yar)).match(str(sample))
    assert "Hashes|contains" in sig.read_text(encoding="utf-8")


def test_session_stores_findings(tmp_path: Path) -> None:
    session_path = tmp_path / "case.octov"
    assert main(["analyze", str(_evasive(tmp_path)), "--session", str(session_path)]) == 0
    with Session.open(session_path) as s:
        [row] = s.list_samples()
        stored = s.get_sample(row.sha256)
        assert stored is not None
        assert any(f["rule_id"] == "EVA-001" for f in stored["findings"])
