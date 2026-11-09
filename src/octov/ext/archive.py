"""Safe zip extraction shared by the capa rules and Ghidra installers."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path, PurePosixPath


class RulesError(Exception):
    """A downloaded or local archive cannot be installed (checksum, unsafe path, bad zip)."""


def _members(
    archive: zipfile.ZipFile, strip_top: bool
) -> list[tuple[zipfile.ZipInfo, PurePosixPath]]:
    names = [PurePosixPath(i.filename) for i in archive.infolist()]
    tops = {n.parts[0] for n in names if n.parts}
    strip = 1 if strip_top and len(tops) == 1 and any(len(n.parts) > 1 for n in names) else 0
    out = []
    for info, name in zip(archive.infolist(), names, strict=True):
        if name.is_absolute() or ".." in name.parts or ":" in info.filename:
            raise RulesError(f"unsafe path in archive: {info.filename}")
        if info.is_dir() or len(name.parts) <= strip:
            continue
        out.append((info, PurePosixPath(*name.parts[strip:])))
    return out


def safe_extract(archive_path: Path, target: Path, strip_top: bool = True) -> None:
    """Extract into ``target``; every name is checked before anything is written."""
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = _members(archive, strip_top)
            for info, rel in members:
                dest = target.joinpath(*rel.parts)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, dest.open("wb") as out:
                    shutil.copyfileobj(src, out)
    except zipfile.BadZipFile as exc:
        raise RulesError(f"not a zip archive: {archive_path}") from exc
