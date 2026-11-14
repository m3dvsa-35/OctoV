"""Child process: FLIRT signature matching for already discovered functions.

``python -m octov.ext.library_worker <sample> <signature dir> <starts file>``

The only module that imports ``flirt``: the FLARE signature sets take several hundred MB once
compiled, so they live in this short-lived process and never in the application. Prints one
JSON document with every candidate name; what is accepted is decided by the caller
(``octov.core.analysis.library.accept``).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import flirt

from octov.core.static.disasm import ImageView
from octov.core.static.pe_parser import parse_pe

DOC_VERSION = 1
WINDOW = 0x8000  # bytes handed to the matcher per function
MAX_NAMES = 4  # names listed per candidate; ``count`` has the real number
_NAME_KINDS = ("public", "local")


def _load(path: Path) -> list[Any]:
    if path.suffix == ".pat":
        return list(flirt.parse_pat(path.read_text(encoding="utf-8", errors="replace")))
    return list(flirt.parse_sig(path.read_bytes()))


def _names(signatures: Sequence[Any]) -> list[str]:
    found = {
        name
        for sig in signatures
        for name, kind, offset in sig.names
        if offset == 0 and kind in _NAME_KINDS and name != "?"
    }
    return sorted(found)


def match_file(sample: Path, sigs_dir: Path, starts: Sequence[int]) -> dict[str, Any]:
    data = sample.read_bytes()
    view = ImageView(data, parse_pe(data))
    sets: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    files = sorted(p for p in sigs_dir.iterdir() if p.suffix in (".sig", ".pat") and p.is_file())
    for path in files:
        signatures = _load(path)
        sets.append({"file": path.name, "signatures": len(signatures)})
        if not signatures:
            continue
        matcher = flirt.compile(signatures)
        del signatures
        for start in sorted(set(starts)):
            ok = start >= 0 and view.is_executable(start)
            buf = view.read_raw(start, WINDOW) if ok else b""  # file bytes only, no padding
            names = _names(matcher.match(buf)) if buf else []
            if names:
                candidates.append(
                    {
                        "rva": start,
                        "set": path.name,
                        "names": names[:MAX_NAMES],
                        "count": len(names),
                    }
                )
        del matcher  # one compiled set in memory at a time
    candidates.sort(key=lambda c: (c["rva"], c["set"]))
    return {"engine": "library", "version": DOC_VERSION, "sets": sets, "candidates": candidates}


def main(argv: Sequence[str]) -> int:
    if len(argv) != 3:
        print("usage: library_worker <sample> <signature dir> <starts file>", file=sys.stderr)
        return 2
    starts = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    if not isinstance(starts, list) or not all(type(s) is int for s in starts):
        print("starts file must be a JSON list of integers", file=sys.stderr)
        return 2
    json.dump(match_file(Path(argv[0]), Path(argv[1]), starts), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
