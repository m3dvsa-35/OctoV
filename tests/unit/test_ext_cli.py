from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from octov.cli.main import main
from octov.ext import capa_rules


def _archive(tmp_path: Path) -> Path:
    path = tmp_path / "rules.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("capa-rules-10.0.0/a/b.yml", "rule: b")
    return path


def test_ext_status_lists_engines(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ext", "status", "--rules-root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "capa" in out and "floss" in out
    assert "octov ext setup capa" in out  # capa has no rules in tmp_path


def test_setup_from_zip_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _archive(tmp_path)
    monkeypatch.setattr(
        capa_rules, "CAPA_RULES_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest()
    )
    root = tmp_path / "rules"
    assert (
        main(
            [
                "ext",
                "setup",
                "capa",
                "--from-zip",
                str(archive),
                "--no-sigs",
                "--rules-root",
                str(root),
            ]
        )
        == 0
    )
    assert str(root / "v10.0.0") in capsys.readouterr().out
    assert (root / "v10.0.0" / "a" / "b.yml").is_file()


def test_setup_bad_checksum_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    archive = _archive(tmp_path)
    code = main(
        [
            "ext",
            "setup",
            "capa",
            "--from-zip",
            str(archive),
            "--no-sigs",
            "--rules-root",
            str(tmp_path / "r"),
        ]
    )
    assert code == 2
    assert "checksum mismatch" in capsys.readouterr().err


def test_setup_installs_sigs_from_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _archive(tmp_path)
    monkeypatch.setattr(
        capa_rules, "CAPA_RULES_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest()
    )
    sigs = tmp_path / "sigs-src"
    sigs.mkdir()
    pins = {}
    for name in capa_rules.CAPA_SIGS:
        (sigs / name).write_bytes(name.encode())
        pins[name] = hashlib.sha256(name.encode()).hexdigest()
    monkeypatch.setattr(capa_rules, "CAPA_SIGS", pins)
    root = tmp_path / "rules"
    args = ["ext", "setup", "capa", "--from-zip", str(archive), "--sigs-from", str(sigs)]
    assert main([*args, "--rules-root", str(root), "--sigs-root", str(tmp_path / "s")]) == 0
    assert "signatures installed" in capsys.readouterr().out
    assert sorted(p.name for p in (tmp_path / "s" / "v10.0.0").iterdir()) == sorted(pins)
