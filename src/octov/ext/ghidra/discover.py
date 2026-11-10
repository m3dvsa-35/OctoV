"""Find a usable JDK (>= 21) and Ghidra 12.x without starting Java in the OctoV process."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from octov.core.config import GhidraConfig
from octov.ext import ExtensionStatus

MIN_JAVA = 21
GHIDRA_MAJOR = "12"
_PROGRAM_FILES = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
DEFAULT_JDK_ROOTS: tuple[Path, ...] = tuple(
    _PROGRAM_FILES / vendor
    for vendor in ("Eclipse Adoptium", "Java", "Microsoft", "Zulu", "Amazon Corretto")
)
_JAVA_VERSION = re.compile(r'^JAVA_VERSION="([^"]+)"', re.M)
_GHIDRA_VERSION = re.compile(r"^application\.version=(\S+)", re.M)


def _numbers(version: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version.split("_")[0])[:3])


def _release_version(home: Path) -> str | None:
    try:
        match = _JAVA_VERSION.search((home / "release").read_text(encoding="utf-8"))
    except OSError:
        return None
    return match[1] if match else None


def java_version(home: Path) -> tuple[int, ...] | None:
    """Version from the JDK's ``release`` file, e.g. ``(25, 0, 1)``; ``None`` if absent."""
    text = _release_version(home)
    return _numbers(text) if text else None


def _usable(home: Path | None) -> tuple[Path, str] | None:
    if home is None:
        return None
    version = java_version(home)
    if version is None or version[0] < MIN_JAVA:
        return None
    return home, _release_version(home) or ""


def find_jdk(
    cfg: GhidraConfig,
    env: Mapping[str, str],
    roots: Sequence[Path] = DEFAULT_JDK_ROOTS,
    which: Callable[[str], str | None] = shutil.which,
) -> tuple[Path, str] | None:
    """(JDK home, version) of the first JDK >= 21: config, JAVA_HOME, vendor dirs, PATH."""
    if found := _usable(cfg.java_home):
        return found
    if found := _usable(Path(env["JAVA_HOME"]) if env.get("JAVA_HOME") else None):
        return found
    candidates: list[tuple[tuple[int, ...], Path]] = []
    for root in roots:
        if not root.is_dir():
            continue
        for child in root.iterdir():
            version = java_version(child)
            if version is not None and version[0] >= MIN_JAVA:
                candidates.append((version, child))
    if candidates:
        home = max(candidates)[1]
        return home, _release_version(home) or ""
    java = which("java")
    return _usable(Path(java).resolve().parent.parent) if java else None


def ghidra_version(install: Path) -> str | None:
    try:
        text = (install / "Ghidra" / "application.properties").read_text(encoding="utf-8")
    except OSError:
        return None
    match = _GHIDRA_VERSION.search(text)
    return match[1] if match else None


def find_ghidra(cfg: GhidraConfig, env: Mapping[str, str], home_root: Path) -> Path | None:
    """Ghidra install dir: config, then ``home_root/ghidra/<newest>/<one dir>``, then env."""
    if cfg.install_dir is not None:
        return cfg.install_dir if ghidra_version(cfg.install_dir) else None
    managed = home_root / "ghidra"
    if managed.is_dir():
        installs = [
            inner
            for version_dir in managed.iterdir()
            if version_dir.is_dir()
            for inner in version_dir.iterdir()
            if inner.is_dir() and ghidra_version(inner)
        ]
        if installs:
            return max(installs, key=lambda p: _numbers(ghidra_version(p) or "0"))
    env_dir = env.get("GHIDRA_INSTALL_DIR")
    if env_dir and ghidra_version(Path(env_dir)):
        return Path(env_dir)
    return None


def ghidra_status(
    cfg: GhidraConfig,
    env: Mapping[str, str] = os.environ,
    home_root: Path | None = None,
    finder: Callable[[str], object | None] = importlib.util.find_spec,
    jdk_roots: Sequence[Path] = DEFAULT_JDK_ROOTS,
    which: Callable[[str], str | None] = shutil.which,
) -> ExtensionStatus:
    home_root = home_root or Path.home() / ".octov"
    installed = finder("pyghidra") is not None
    install = find_ghidra(cfg, env, home_root)
    version = ghidra_version(install) if install else None
    jdk = find_jdk(cfg, env, jdk_roots, which)
    reason: str | None = None
    if not installed:
        reason = "ext.reason.not_installed"
    elif install is None:
        reason = "ext.reason.no_ghidra"
    elif not (version or "").startswith(GHIDRA_MAJOR + "."):
        reason = "ext.reason.ghidra_version"
    elif jdk is None:
        reason = "ext.reason.no_jdk"
    return ExtensionStatus(
        id="ghidra",
        installed=installed,
        ready=reason is None,
        version=version,
        rules_version=jdk[1] if jdk else None,
        reason_key=reason,
        install_cmd="python -m uv sync --extra ghidra",
        setup_cmd="octov ext setup ghidra",
    )
