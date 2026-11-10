"""One-time Ghidra installation (``octov ext setup ghidra``); the workbench never downloads."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from octov.ext.archive import RulesError, safe_extract
from octov.ext.capa_rules import _download, _sha256

GHIDRA_VERSION = "12.2"
GHIDRA_URL = (
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
    "Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip"
)
GHIDRA_SIZE = 569_712_708
GHIDRA_SHA256 = "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"


def install_ghidra(
    home_root: Path,
    zip_path: Path | None = None,
    fetch: Callable[[str, Path], None] | None = None,
) -> Path:
    """Verify and unpack Ghidra into ``home_root/ghidra/<version>/`` (atomic replace)."""
    root = home_root / "ghidra"
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root, prefix=".setup-") as tmp:
        work = Path(tmp)
        archive = zip_path
        if archive is None:
            archive = work / "ghidra.zip"
            (fetch or _download)(GHIDRA_URL, archive)
        digest = _sha256(archive)
        if digest != GHIDRA_SHA256:
            raise RulesError(f"checksum mismatch: expected {GHIDRA_SHA256}, got {digest}")
        staged = work / "staged"
        safe_extract(archive, staged, strip_top=False)
        target = root / GHIDRA_VERSION
        if target.exists():
            shutil.rmtree(target)
        staged.replace(target)
    return target
