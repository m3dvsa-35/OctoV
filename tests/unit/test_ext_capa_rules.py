from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from octov.ext import capa_rules
from octov.ext.capa_rules import RulesError, install_rules


def _zip(path: Path, members: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return path


def _pin(monkeypatch: pytest.MonkeyPatch, archive: Path) -> None:
    monkeypatch.setattr(
        capa_rules, "CAPA_RULES_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest()
    )


GOOD = {
    "capa-rules-10.0.0/": "",
    "capa-rules-10.0.0/nursery/x.yml": "rule: x",
    "capa-rules-10.0.0/host-interaction/y.yml": "rule: y",
    "capa-rules-10.0.0/README.md": "readme",
}


def test_pinned_release() -> None:
    assert capa_rules.CAPA_RULES_VERSION == "v10.0.0"
    assert capa_rules.CAPA_RULES_URL.endswith("/capa-rules/archive/refs/tags/v10.0.0.zip")
    assert len(capa_rules.CAPA_RULES_SHA256) == 64


def test_from_zip_installs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = _zip(tmp_path / "r.zip", GOOD)
    _pin(monkeypatch, archive)
    target = install_rules(tmp_path / "rules", zip_path=archive)
    assert target == tmp_path / "rules" / "v10.0.0"
    assert (target / "nursery" / "x.yml").read_text(encoding="utf-8") == "rule: x"
    assert (target / "host-interaction" / "y.yml").is_file()


def test_download_uses_fetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = _zip(tmp_path / "r.zip", GOOD)
    _pin(monkeypatch, archive)
    seen: list[str] = []

    def fetch(url: str, dest: Path) -> None:
        seen.append(url)
        dest.write_bytes(archive.read_bytes())

    target = install_rules(tmp_path / "rules", fetch=fetch)
    assert seen == [capa_rules.CAPA_RULES_URL]
    assert (target / "nursery" / "x.yml").is_file()


def test_checksum_mismatch_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "r.zip", GOOD)
    with pytest.raises(RulesError, match="checksum mismatch"):
        install_rules(tmp_path / "rules", zip_path=archive)
    assert not (tmp_path / "rules" / "v10.0.0").exists()


def test_zip_slip_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = _zip(tmp_path / "r.zip", {**GOOD, "capa-rules-10.0.0/../../evil.yml": "x"})
    _pin(monkeypatch, archive)
    with pytest.raises(RulesError, match="unsafe path in archive"):
        install_rules(tmp_path / "rules", zip_path=archive)
    assert not (tmp_path / "evil.yml").exists()
    assert not (tmp_path / "rules" / "v10.0.0").exists()


def test_reinstall_replaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = _zip(tmp_path / "r.zip", GOOD)
    _pin(monkeypatch, archive)
    target = install_rules(tmp_path / "rules", zip_path=archive)
    (target / "stale.yml").write_text("old", encoding="utf-8")
    install_rules(tmp_path / "rules", zip_path=archive)
    assert not (target / "stale.yml").exists()


def test_unpinned_local_zip(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "r.zip", GOOD)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    target = install_rules(tmp_path / "rules", zip_path=archive, allow_unpinned=True)
    assert target.name == f"local-{digest[:12]}"
    assert (target / "nursery" / "x.yml").is_file()
