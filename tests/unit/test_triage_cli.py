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
    "recovered_strings",
    "payloads",
    "top_functions",
    "library",
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


@pytest.fixture
def fake_capa(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, int]:
    import sys

    from octov.app import api as api_mod
    from octov.ext import capa as capa_ext
    from tests.unit.test_ext_api import FAKE, FIXTURES, _status

    started = {"capa": 0}

    def capa_cmd(path: Path, rules: Path, sigs: Path, *, raw: bool, bits: int) -> list[str]:
        started["capa"] += 1
        return [sys.executable, FAKE, "file", str(FIXTURES / "capa" / "synthetic_injector.json")]

    monkeypatch.setattr(capa_ext, "capa_command", capa_cmd)
    monkeypatch.setattr(api_mod, "extension_status", lambda root: _status({"capa"}))
    monkeypatch.setattr(api_mod, "capa_rules_dir", lambda root: ("v10.0.0", tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # cache under tmp, not the real profile
    monkeypatch.setenv("HOME", str(tmp_path))
    return started


def test_triage_waits_for_capa(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fake_capa: dict[str, int]
) -> None:
    from tests.unit.test_triage_api import _suspicious

    assert main(["triage", str(_suspicious(tmp_path)), "--md"]) == 0
    out = capsys.readouterr().out
    assert "## Capabilities (capa)" in out
    assert "create thread" in out
    assert "### host-interaction" in out
    assert fake_capa["capa"] == 1


def test_no_ext_skips_engines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fake_capa: dict[str, int]
) -> None:
    from tests.unit.test_triage_api import _suspicious

    assert main(["triage", str(_suspicious(tmp_path)), "--no-ext"]) == 0
    out = capsys.readouterr().out
    assert fake_capa["capa"] == 0
    assert "Capabilities (capa)" not in out
