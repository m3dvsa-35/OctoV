from __future__ import annotations

from pathlib import Path

from octov.ext import ENGINES, capa_rules_dir, capa_sigs_dir, extension_status


def _status(tmp_path: Path, **kw: object) -> dict[str, object]:
    return {s.id: s for s in extension_status(tmp_path, **kw)}  # type: ignore[arg-type]


def test_engine_order() -> None:
    assert ENGINES == ("floss", "capa")


def test_missing_engine_is_not_installed(tmp_path: Path) -> None:
    st = _status(tmp_path, finder=lambda name: None)
    capa = st["capa"]
    assert not capa.installed and not capa.ready  # type: ignore[attr-defined]
    assert capa.reason_key == "ext.reason.not_installed"  # type: ignore[attr-defined]
    assert capa.install_cmd == "python -m uv sync --extra capa"  # type: ignore[attr-defined]
    assert capa.setup_cmd == "octov ext setup capa"  # type: ignore[attr-defined]
    assert st["floss"].setup_cmd is None  # type: ignore[attr-defined]


def test_capa_without_rules_is_not_ready(tmp_path: Path) -> None:
    st = _status(tmp_path, finder=lambda name: object(), version_of=lambda name: "10.0.0")
    capa, floss = st["capa"], st["floss"]
    assert capa.installed and not capa.ready  # type: ignore[attr-defined]
    assert capa.reason_key == "ext.reason.no_rules"  # type: ignore[attr-defined]
    assert floss.ready and floss.reason_key is None  # type: ignore[attr-defined]
    assert floss.version == "10.0.0"  # type: ignore[attr-defined]


def test_capa_with_rules_is_ready(tmp_path: Path) -> None:
    (tmp_path / "v10.0.0").mkdir()
    (tmp_path / "v10.0.0" / "a.yml").write_text("x", encoding="utf-8")
    st = _status(tmp_path, finder=lambda name: object(), version_of=lambda name: "10.0.0")
    assert st["capa"].ready and st["capa"].rules_version == "v10.0.0"  # type: ignore[attr-defined]


def test_capa_rules_dir_picks_newest_with_yml(tmp_path: Path) -> None:
    for name, yml in (("v9.0.0", True), ("v10.0.0", True), ("v11.0.0", False), ("junk", True)):
        (tmp_path / name).mkdir()
        if yml:
            (tmp_path / name / "rule.yml").write_text("x", encoding="utf-8")
    found = capa_rules_dir(tmp_path)
    assert found is not None and found[0] == "v10.0.0"


def test_rules_dir_missing_root(tmp_path: Path) -> None:
    assert capa_rules_dir(tmp_path / "nope") is None


def test_local_rules_dir_wins(tmp_path: Path) -> None:
    for name in ("v10.0.0", "local-0123456789ab"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "rule.yml").write_text("x", encoding="utf-8")
    found = capa_rules_dir(tmp_path)
    assert found is not None and found[0] == "local-0123456789ab"


def test_capa_sigs_dir(tmp_path: Path) -> None:
    assert capa_sigs_dir(tmp_path, None) is None
    assert capa_sigs_dir(tmp_path, "v10.0.0") is None
    (tmp_path / "v10.0.0").mkdir()
    (tmp_path / "v10.0.0" / "a.sig").write_bytes(b"x")
    assert capa_sigs_dir(tmp_path, "v10.0.0") == tmp_path / "v10.0.0"
