"""Optional analysis engines (capa, FLOSS) run as isolated child processes.

Nothing here imports an engine: availability is probed with ``find_spec`` and
``importlib.metadata`` so vivisect never loads into the OctoV process.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ENGINES = ("floss", "capa")  # lane order: strings first, they are cheaper
_MODULE = {"capa": "capa", "floss": "floss"}
_DISTRIBUTION = {"capa": "flare-capa", "floss": "flare-floss"}
_VERSION_DIR = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


@dataclass(frozen=True)
class ExtensionStatus:
    id: str
    installed: bool
    ready: bool
    version: str | None
    rules_version: str | None
    reason_key: str | None
    install_cmd: str
    setup_cmd: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def capa_rules_dir(rules_root: Path) -> tuple[str, Path] | None:
    """Newest ``<version>/`` under ``rules_root`` that contains at least one ``*.yml``."""
    if not rules_root.is_dir():
        return None
    found: list[tuple[tuple[int, int, int], str, Path]] = []
    for child in rules_root.iterdir():
        match = _VERSION_DIR.match(child.name)
        if match and child.is_dir() and next(child.rglob("*.yml"), None) is not None:
            key = (int(match[1]), int(match[2]), int(match[3]))
            found.append((key, child.name, child))
    if not found:
        return None
    _, name, path = max(found)
    return name, path


def _version(version_of: Callable[[str], str], engine: str) -> str | None:
    try:
        return version_of(_DISTRIBUTION[engine])
    except importlib.metadata.PackageNotFoundError:
        return None


def extension_status(
    rules_root: Path,
    finder: Callable[[str], object | None] = importlib.util.find_spec,
    version_of: Callable[[str], str] = importlib.metadata.version,
) -> list[ExtensionStatus]:
    out = []
    for engine in ENGINES:
        installed = finder(_MODULE[engine]) is not None
        rules = capa_rules_dir(rules_root) if engine == "capa" else None
        reason: str | None = None
        if not installed:
            reason = "ext.reason.not_installed"
        elif engine == "capa" and rules is None:
            reason = "ext.reason.no_rules"
        out.append(
            ExtensionStatus(
                id=engine,
                installed=installed,
                ready=reason is None,
                version=_version(version_of, engine) if installed else None,
                rules_version=rules[0] if rules else None,
                reason_key=reason,
                install_cmd=f"python -m uv sync --extra {engine}",
                setup_cmd="octov ext setup capa" if engine == "capa" else None,
            )
        )
    return out
