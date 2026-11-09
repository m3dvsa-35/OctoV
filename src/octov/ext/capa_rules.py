"""One-time installation of the capa rule set (the capa wheel ships no rules).

Only ``octov ext setup capa`` calls this; the workbench never touches the network.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

# Matches flare-capa 10.x. Pinned 2026-11-09 (739434 bytes, 1057 rules).
CAPA_RULES_VERSION = "v10.0.0"
CAPA_RULES_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/v10.0.0.zip"
CAPA_RULES_SHA256 = "c27974b03020dd563125b40b20d26eeaee13a5cc5c0c2be1d1a7ee57098cbd2f"


class RulesError(Exception):
    pass


def _download(url: str, dest: Path) -> None:
    with urllib.request.urlopen(url, timeout=120) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _members(archive: zipfile.ZipFile) -> list[tuple[zipfile.ZipInfo, PurePosixPath]]:
    """Archive files with their path below the single top-level folder (if any)."""
    names = [PurePosixPath(i.filename) for i in archive.infolist()]
    tops = {n.parts[0] for n in names if n.parts}
    strip = 1 if len(tops) == 1 and any(len(n.parts) > 1 for n in names) else 0
    out = []
    for info, name in zip(archive.infolist(), names, strict=True):
        if name.is_absolute() or ".." in name.parts or ":" in info.filename:
            raise RulesError(f"unsafe path in archive: {info.filename}")
        if info.is_dir() or len(name.parts) <= strip:
            continue
        out.append((info, PurePosixPath(*name.parts[strip:])))
    return out


def install_rules(
    rules_root: Path,
    zip_path: Path | None = None,
    fetch: Callable[[str, Path], None] = _download,
    allow_unpinned: bool = False,
) -> Path:
    rules_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=rules_root, prefix=".setup-") as tmp:
        work = Path(tmp)
        archive_path = zip_path
        if archive_path is None:
            archive_path = work / "rules.zip"
            fetch(CAPA_RULES_URL, archive_path)
        digest = _sha256(archive_path)
        if digest != CAPA_RULES_SHA256 and not allow_unpinned:
            raise RulesError(
                f"checksum mismatch: expected {CAPA_RULES_SHA256}, got {digest} "
                "(use --allow-unpinned for a different local rules archive)"
            )
        version = CAPA_RULES_VERSION if digest == CAPA_RULES_SHA256 else f"local-{digest[:12]}"
        staged = work / "staged"
        try:
            with zipfile.ZipFile(archive_path) as archive:
                for info, rel in _members(archive):
                    dest = staged.joinpath(*rel.parts)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as src, dest.open("wb") as out:
                        shutil.copyfileobj(src, out)
        except zipfile.BadZipFile as exc:
            raise RulesError(f"not a zip archive: {archive_path}") from exc
        target = rules_root / version
        if target.exists():
            shutil.rmtree(target)
        staged.replace(target)
    return target
