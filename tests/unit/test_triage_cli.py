from __future__ import annotations

import json
from pathlib import Path

import pytest

from octov.cli.main import main
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

KEYS = {
    "score",
    "packer",
    "capabilities",
    "iocs",
    "iocs_total",
    "payloads",
    "top_functions",
    "attack",
    "orphaned_verdicts",
    "jobs",
}


def _sample(tmp_path: Path) -> Path:
    path = tmp_path / "s.exe"
    path.write_bytes(
        build_pe(
            PESpec(
                sections=[
                    SectionSpec(".text", b"\xc3", TEXT),
                    SectionSpec(".data", b"http://x.example/gate.php\x00", DATA),
                ],
                imports={"kernel32.dll": ["WriteProcessMemory", "CreateRemoteThread"]},
            )
        )
    )
    return path


def test_triage_json_has_report_keys(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["triage", str(_sample(tmp_path)), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) == KEYS
    assert out["jobs"]["ranking"]["state"] in ("done", "unavailable")


def test_triage_markdown(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["triage", str(_sample(tmp_path)), "--md"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Triage: s.exe")
    assert "## IOCs" in out and "x.example" in out


def test_triage_text_and_ioc_csv(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    csv_path = tmp_path / "iocs.csv"
    assert main(["triage", str(_sample(tmp_path)), "--iocs", str(csv_path)]) == 0
    out = capsys.readouterr().out
    assert "Risk" in out and "process_injection_apis" in out
    assert csv_path.read_text(encoding="utf-8").startswith("type,value,offsets,benign_hint")


def test_triage_non_pe_suggests_raw(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"\x90" * 64)
    assert main(["triage", str(blob)]) == 2
    assert "raw" in capsys.readouterr().err
    assert main(["triage", str(blob), "--raw", "--json"]) == 0


def test_triage_json_lists_every_ioc(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The UI payload is capped; the CLI report is not."""
    urls = b"".join(b"http://host%04d.example/p\x00" % i for i in range(150))
    path = tmp_path / "many.exe"
    path.write_bytes(build_pe(PESpec(sections=[SectionSpec(".data", urls, DATA)])))
    assert main(["triage", str(path), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["iocs_total"] == 300
    assert len(out["iocs"]) == 300
