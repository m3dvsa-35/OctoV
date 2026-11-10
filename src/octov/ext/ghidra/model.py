"""Decompiled-function model, per-line marks for beginners and the pseudo-C cache key."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from octov.core.analysis.facts import Fact
from octov.core.analysis.naming import API_FAMILIES
from octov.core.analysis.scoring import SUSPICIOUS_FAMILIES
from octov.ext import cache
from octov.ext.ghidra.protocol import ERROR_KINDS, ErrorKind, GhidraError


@dataclass(frozen=True)
class Line:
    text: str
    rvas: tuple[int, ...]  # instruction addresses Ghidra attributes to this line


@dataclass(frozen=True)
class DecompiledFunction:
    entry_rva: int
    name: str
    lines: tuple[Line, ...]
    warnings: tuple[str, ...]

    @classmethod
    def from_reply(cls, reply: Mapping[str, Any]) -> DecompiledFunction:
        """A worker ``decompile`` reply; an error reply raises :class:`GhidraError`."""
        if not reply.get("ok"):
            kind = str(reply.get("error"))
            raise GhidraError(
                cast(ErrorKind, kind if kind in ERROR_KINDS else "decompile_failed"),
                str(reply.get("detail") or kind),
            )
        try:
            return cls(
                entry_rva=int(reply["entry_rva"]),
                name=str(reply["name"]),
                lines=tuple(
                    Line(str(text), tuple(int(r) for r in rvas)) for text, rvas in reply["lines"]
                ),
                warnings=tuple(str(w) for w in reply.get("warnings", ())),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GhidraError("crash", "unexpected worker output") from exc

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> DecompiledFunction | None:
        """The inverse of :meth:`to_dict`; ``None`` for a damaged cache entry."""
        try:
            return cls(
                entry_rva=int(doc["entry_rva"]),
                name=str(doc["name"]),
                lines=tuple(
                    Line(str(ln["text"]), tuple(int(r) for r in ln["rvas"])) for ln in doc["lines"]
                ),
                warnings=tuple(str(w) for w in doc.get("warnings", ())),
            )
        except (KeyError, TypeError, ValueError):
            return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_rva": self.entry_rva,
            "name": self.name,
            "lines": [{"text": ln.text, "rvas": list(ln.rvas)} for ln in self.lines],
            "warnings": list(self.warnings),
        }


def annotation_hash(names: Mapping[int, str], comments: Mapping[int, str]) -> str:
    """Identifies the analyst names/comments a pseudo-C text was produced with."""
    doc = {
        "names": sorted((int(rva), text) for rva, text in names.items()),
        "comments": sorted((int(rva), text) for rva, text in comments.items()),
    }
    payload = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def cache_path(cache_dir: Path, sha: str, ghidra_version: str, ahash: str, entry_rva: int) -> Path:
    folder = cache.cache_file(cache_dir, sha, "ghidra", ghidra_version, ahash)
    return folder.with_name(folder.name.removesuffix(".json.gz")) / f"{entry_rva:x}.json.gz"


def suspicious_apis() -> dict[str, str]:
    """Normalised API name -> family, for the families OctoV ranks as suspicious."""
    return {
        api: family
        for family, apis in API_FAMILIES.items()
        if family in SUSPICIOUS_FAMILIES
        for api in apis
    }


@lru_cache(maxsize=8)
def _call_pattern(names: tuple[str, ...]) -> re.Pattern[str]:
    longest_first = sorted(names, key=lambda n: (-len(n), n))
    return re.compile(rf"\b({'|'.join(map(re.escape, longest_first))})[AW]?\s*\(")


def line_marks(
    fn: DecompiledFunction, facts: Sequence[Fact], api_names: Mapping[str, str]
) -> list[list[dict[str, Any]]]:
    """Per line: facts whose evidence sits on it, then calls to APIs in ``api_names``."""
    by_rva: dict[int, list[Fact]] = {}
    for fact in facts:
        for rva in {e.rva for e in fact.evidence if e.rva is not None}:
            by_rva.setdefault(rva, []).append(fact)
    pattern = _call_pattern(tuple(sorted(api_names))) if api_names else None
    result: list[list[dict[str, Any]]] = []
    for line in fn.lines:
        marks: list[dict[str, Any]] = []
        seen: set[str] = set()
        for rva in line.rvas:
            for fact in by_rva.get(rva, ()):
                if fact.id not in seen:
                    seen.add(fact.id)
                    marks.append({"kind": "fact", "fact_id": fact.id, "severity": fact.severity})
        if pattern is not None:
            for api in dict.fromkeys(m[1] for m in pattern.finditer(line.text)):
                marks.append({"kind": "api", "api": api, "family": api_names[api]})
        result.append(marks)
    return result
