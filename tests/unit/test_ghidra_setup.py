from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from octov.cli.main import main
from octov.ext.archive import RulesError, safe_extract
from octov.ext.ghidra import setup
from octov.ext.ghidra.discover import ghidra_version

PROPS = "ghidra_12.2_PUBLIC/Ghidra/application.properties"


def _zip(path: Path, members: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return path


def _pin(monkeypatch: pytest.MonkeyPatch, archive: Path) -> None:
    monkeypatch.setattr(setup, "GHIDRA_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest())


def test_pinned_release() -> None:
    assert setup.GHIDRA_VERSION == "12.2"
    assert setup.GHIDRA_SIZE == 569_712_708
    assert setup.GHIDRA_SHA256 == "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"
    assert setup.GHIDRA_URL.endswith("/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip")


def test_install_from_zip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = _zip(tmp_path / "g.zip", {PROPS: "application.version=12.2\n"})
    _pin(monkeypatch, archive)
    target = setup.install_ghidra(tmp_path / "home", zip_path=archive)
    assert target == tmp_path / "home" / "ghidra" / "12.2"
    assert ghidra_version(target / "ghidra_12.2_PUBLIC") == "12.2"


def test_checksum_mismatch(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "g.zip", {PROPS: "application.version=12.2\n"})
    with pytest.raises(RulesError, match="checksum mismatch"):
        setup.install_ghidra(tmp_path / "home", zip_path=archive)
    assert not (tmp_path / "home" / "ghidra" / "12.2").exists()


def test_zip_slip_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "g.zip", {"../evil.txt": "x"})
    with pytest.raises(RulesError, match="unsafe path"):
        safe_extract(archive, tmp_path / "out", strip_top=False)
    assert not (tmp_path / "evil.txt").exists()


def test_setup_ghidra_prints_size_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _zip(tmp_path / "g.zip", {PROPS: "application.version=12.2\n"})
    _pin(monkeypatch, archive)

    def fetch(url: str, dest: Path) -> None:
        print("fetching")
        dest.write_bytes(archive.read_bytes())

    monkeypatch.setattr(setup, "_download", fetch)
    home = tmp_path / "home"
    assert main(["ext", "setup", "ghidra", "--home-root", str(home)]) == 0
    out = capsys.readouterr().out
    assert out.index("543 MiB") < out.index("fetching") < out.index("installed")
