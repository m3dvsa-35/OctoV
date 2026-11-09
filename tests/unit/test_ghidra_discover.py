from __future__ import annotations

from pathlib import Path

from octov.core.config import GhidraConfig
from octov.ext.ghidra.discover import (
    find_ghidra,
    find_jdk,
    ghidra_status,
    ghidra_version,
    java_version,
)


def _jdk(root: Path, name: str, version: str) -> Path:
    home = root / name
    (home / "bin").mkdir(parents=True)
    (home / "release").write_text(
        f'JAVA_VERSION="{version}"\nOS_NAME="Windows"\n', encoding="utf-8"
    )
    return home


def _ghidra(root: Path, version: str) -> Path:
    install = root / f"ghidra_{version}_PUBLIC"
    (install / "Ghidra").mkdir(parents=True)
    (install / "Ghidra" / "application.properties").write_text(
        f"application.name=Ghidra\napplication.version={version}\n", encoding="utf-8"
    )
    return install


def test_java_version_from_release_file(tmp_path: Path) -> None:
    assert java_version(_jdk(tmp_path, "a", "25.0.1")) == (25, 0, 1)
    assert java_version(_jdk(tmp_path, "b", "1.8.0_401")) == (1, 8, 0)
    assert java_version(tmp_path / "missing") is None


def test_find_jdk_skips_old_java_home_and_finds_adoptium(tmp_path: Path) -> None:
    old = _jdk(tmp_path / "java8", "jre1.8", "1.8.0_401")
    adoptium = tmp_path / "Eclipse Adoptium"
    _jdk(adoptium, "jdk-21.0.4.7-hotspot", "21.0.4")
    newest = _jdk(adoptium, "jdk-25.0.1.8-hotspot", "25.0.1")
    found = find_jdk(
        GhidraConfig(), {"JAVA_HOME": str(old)}, roots=[adoptium], which=lambda n: None
    )
    assert found == (newest, "25.0.1")


def test_find_jdk_config_wins(tmp_path: Path) -> None:
    mine = _jdk(tmp_path, "mine", "21.0.2")
    other = _jdk(tmp_path / "roots", "jdk-25", "25.0.1")
    cfg = GhidraConfig(java_home=mine)
    assert find_jdk(cfg, {}, roots=[other.parent], which=lambda n: None) == (mine, "21.0.2")


def test_no_jdk_21(tmp_path: Path) -> None:
    old = _jdk(tmp_path, "jdk-17", "17.0.9")
    assert (
        find_jdk(GhidraConfig(), {"JAVA_HOME": str(old)}, roots=[tmp_path], which=lambda n: None)
        is None
    )


def test_java_on_path_is_used_last(tmp_path: Path) -> None:
    home = _jdk(tmp_path, "pathjdk", "22.0.1")
    java = home / "bin" / "java.exe"
    java.write_bytes(b"")
    assert find_jdk(GhidraConfig(), {}, roots=[], which=lambda n: str(java)) == (home, "22.0.1")


def test_ghidra_version_from_properties(tmp_path: Path) -> None:
    assert ghidra_version(_ghidra(tmp_path, "12.2")) == "12.2"
    assert ghidra_version(tmp_path / "nope") is None


def test_find_ghidra_order(tmp_path: Path) -> None:
    configured = _ghidra(tmp_path / "cfg", "12.1")
    home_root = tmp_path / "octov"
    managed = _ghidra(home_root / "ghidra" / "12.2", "12.2").parent
    env_dir = _ghidra(tmp_path / "env", "12.0")
    assert find_ghidra(GhidraConfig(install_dir=configured), {}, home_root) == configured
    found = find_ghidra(GhidraConfig(), {"GHIDRA_INSTALL_DIR": str(env_dir)}, home_root)
    assert found is not None and found.parent == managed
    assert (
        find_ghidra(GhidraConfig(), {"GHIDRA_INSTALL_DIR": str(env_dir)}, tmp_path / "x") == env_dir
    )
    assert find_ghidra(GhidraConfig(), {}, tmp_path / "x") is None


def test_status_reasons(tmp_path: Path) -> None:
    jdk = _jdk(tmp_path / "jdks", "jdk-25", "25.0.1")
    good = _ghidra(tmp_path / "g12", "12.2")
    old = _ghidra(tmp_path / "g11", "11.4")
    env = {"JAVA_HOME": str(jdk)}
    home = tmp_path / "home"

    def status(cfg: GhidraConfig, finder=lambda n: object(), env=env):  # type: ignore[no-untyped-def]
        return ghidra_status(
            cfg, env=env, home_root=home, finder=finder, jdk_roots=[], which=lambda n: None
        )

    assert (
        status(GhidraConfig(install_dir=good), finder=lambda n: None).reason_key
        == "ext.reason.not_installed"
    )
    assert status(GhidraConfig()).reason_key == "ext.reason.no_ghidra"
    assert status(GhidraConfig(install_dir=old)).reason_key == "ext.reason.ghidra_version"
    assert status(GhidraConfig(install_dir=good), env={}).reason_key == "ext.reason.no_jdk"
    ready = status(GhidraConfig(install_dir=good))
    assert ready.ready and ready.id == "ghidra"
    assert (ready.version, ready.rules_version) == ("12.2", "25.0.1")
    assert ready.install_cmd == "python -m uv sync --extra ghidra"
    assert ready.setup_cmd == "octov ext setup ghidra"
