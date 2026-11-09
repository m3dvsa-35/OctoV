"""Machine-local cache of raw engine output (gzip JSON), keyed by sample and versions."""

from __future__ import annotations

import gzip
import json
import os
import re
import tempfile
import zlib
from pathlib import Path
from typing import Any

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def _clean(value: str) -> str:
    return _UNSAFE.sub("_", value)


def cache_file(
    root: Path, sha: str, engine: str, engine_version: str, rules_version: str | None
) -> Path:
    name = f"{_clean(engine)}-{_clean(engine_version)}-{_clean(rules_version or 'none')}.json.gz"
    return root / _clean(sha) / name


def load(path: Path) -> dict[str, Any] | None:
    """The cached document, or ``None`` when missing, unreadable or not a JSON object."""
    try:
        doc = json.loads(gzip.decompress(path.read_bytes()).decode("utf-8"))
    except (OSError, EOFError, zlib.error, UnicodeDecodeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def store(path: Path, doc: dict[str, Any]) -> None:
    """Write atomically: serialise first, then temp file + ``os.replace``."""
    payload = gzip.compress(json.dumps(doc).encode("utf-8"))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".gz")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
