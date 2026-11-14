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


def _probe(monkeypatch: pytest.MonkeyPatch, installed: bool) -> None:
    """Pin the engine probe: the result must not depend on what this machine has installed."""
    from octov import ext
    from octov.cli import ext as ext_cli

    def status(root: Path) -> list[ext.ExtensionStatus]:
        return ext.extension_status(
            root,
            finder=lambda name: object() if installed else None,
            version_of=lambda name: "10.0.0",
        )

    monkeypatch.setattr(ext_cli, "extension_status", status)


def test_ext_status_installed_without_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _probe(monkeypatch, installed=True)
    assert main(["ext", "status", "--rules-root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "floss  ready" in out
    assert "octov ext setup capa" in out  # capa has no rules in tmp_path


def test_ext_status_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _probe(monkeypatch, installed=False)
    assert main(["ext", "status", "--rules-root", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "python -m uv sync --extra capa" in out
    assert "python -m uv sync --extra floss" in out


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


def test_status_lists_ghidra(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from octov.cli import ext as ext_cli
    from octov.ext import ExtensionStatus

    _probe(monkeypatch, installed=True)
    ready = ExtensionStatus(
        "ghidra", True, True, "12.2", "25.0.1", None, "", "octov ext setup ghidra"
    )
    monkeypatch.setattr(ext_cli, "ghidra_status", lambda cfg, **kw: ready)
    assert main(["ext", "status", "--rules-root", str(tmp_path)]) == 0
    assert "ghidra ready (Ghidra 12.2, JDK 25.0.1)" in capsys.readouterr().out


def _fake_sigs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict[str, str]]:
    sigs = tmp_path / "sigs-src"
    sigs.mkdir()
    pins = {}
    for name in capa_rules.CAPA_SIGS:
        (sigs / name).write_bytes(name.encode())
        pins[name] = hashlib.sha256(name.encode()).hexdigest()
    monkeypatch.setattr(capa_rules, "CAPA_SIGS", pins)
    return sigs, pins


def test_setup_library_installs_only_signatures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sigs, pins = _fake_sigs(tmp_path, monkeypatch)
    rules, target = tmp_path / "rules", tmp_path / "s"
    args = ["ext", "setup", "library", "--sigs-from", str(sigs)]
    assert main([*args, "--rules-root", str(rules), "--sigs-root", str(target)]) == 0
    assert "signatures installed" in capsys.readouterr().out
    assert sorted(p.name for p in (target / "v10.0.0").iterdir()) == sorted(pins)
    assert not rules.exists()  # no capa rules were touched


def test_setup_library_bad_checksum_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sigs, pins = _fake_sigs(tmp_path, monkeypatch)
    (sigs / next(iter(pins))).write_bytes(b"tampered")
    args = ["ext", "setup", "library", "--sigs-from", str(sigs), "--sigs-root", str(tmp_path / "s")]
    assert main(args) == 2
    assert "checksum mismatch" in capsys.readouterr().err
    assert not (tmp_path / "s" / "v10.0.0").exists()


def test_status_lists_library(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _probe(monkeypatch, installed=True)
    root = tmp_path / "s"
    base = ["ext", "status", "--rules-root", str(tmp_path), "--sigs-root", str(root)]
    assert main(base) == 0
    assert "library signatures missing: octov ext setup library" in capsys.readouterr().out
    (root / "v10.0.0").mkdir(parents=True)
    (root / "v10.0.0" / "a.sig").write_bytes(b"")
    assert main(base) == 0
    assert "library ready (signatures v10.0.0)" in capsys.readouterr().out
