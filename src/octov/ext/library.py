"""Library-function recognition adapter: status, command line, result-document parser.

Never imports ``flirt`` (see ``library_worker``): availability is probed with ``find_spec``.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from octov.core.analysis.library import Candidate
from octov.ext import ExtensionStatus
from octov.ext.runner import EngineError

WORKER_VERSION = "1"  # bump when the worker's document changes: old cache files are ignored
_VERSION_DIR = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_SIG_SUFFIXES = (".sig", ".pat")


def library_sigs_dir(sigs_root: Path) -> tuple[str, Path] | None:
    """Newest ``<version>/`` under ``sigs_root`` that holds a signature file."""
    if not sigs_root.is_dir():
        return None
    found: list[tuple[tuple[int, int, int], str, Path]] = []
    for child in sigs_root.iterdir():
        match = _VERSION_DIR.match(child.name)
        if not match or not child.is_dir():
            continue
        if not any(p.suffix in _SIG_SUFFIXES for p in child.iterdir()):
            continue
        found.append(((int(match[1]), int(match[2]), int(match[3])), child.name, child))
    if not found:
        return None
    _, name, path = max(found)
    return name, path


def library_status(
    sigs_root: Path, finder: Callable[[str], object | None] = importlib.util.find_spec
) -> ExtensionStatus:
    installed = finder("flirt") is not None
    sigs = library_sigs_dir(sigs_root)
    reason: str | None = None
    if not installed:
        reason = "ext.reason.not_installed"
    elif sigs is None:
        reason = "ext.reason.no_signatures"
    return ExtensionStatus(
        id="library",
        installed=installed,
        ready=reason is None,
        version=WORKER_VERSION if installed else None,
        rules_version=sigs[0] if sigs else None,
        reason_key=reason,
        install_cmd="python -m uv sync",
        setup_cmd="octov ext setup library",
    )


def library_command(sample: Path, sigs: Path, starts_file: Path) -> list[str]:
    worker = "octov.ext.library_worker"
    return [sys.executable, "-m", worker, str(sample), str(sigs), str(starts_file)]


def _bad() -> EngineError:
    return EngineError("bad_output", "unexpected engine output")


def parse_library(doc: dict[str, Any]) -> list[Candidate]:
    """Candidates of the worker's document; anything else is ``bad_output``."""
    rows = doc.get("candidates")
    if doc.get("engine") != "library" or doc.get("version") != 1 or not isinstance(rows, list):
        raise _bad()
    out = []
    for row in rows:
        if not isinstance(row, dict):
            raise _bad()
        rva, sig, names, count = (row.get(k) for k in ("rva", "set", "names", "count"))
        if (
            type(rva) is not int
            or type(count) is not int
            or not isinstance(sig, str)
            or not isinstance(names, list)
            or not names
            or not all(isinstance(n, str) and n for n in names)
        ):
            raise _bad()
        out.append(Candidate(rva, sig, tuple(names), count))
    return out
