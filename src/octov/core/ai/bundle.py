"""The evidence bundle: exactly what the AI analyst is given, and nothing else.

The bundle is built from analysis results only (never the binary or raw bytes), is bounded in
size, and its ``text`` is both what the analyst sees in the preview and the message that is
sent, byte for byte. ``hash`` identifies it: the confirmation and the cache are keyed on it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any, Literal

from octov.core.analysis.facts import Fact

MAX_FINDINGS = 60
MAX_FUNCTIONS = 13
MAX_NEIGHBOURS = 8
MAX_STRINGS = 8
MAX_STRING_CHARS = 120
MAX_IOCS = 40
MAX_NOTES = 40
MAX_CODE_CHARS = 2500
MAX_EVIDENCE = 3
_SEVERITY = {"high": 0, "medium": 1, "low": 2, "info": 3}
_CUT = "\n… (cut)"


@dataclass(frozen=True)
class FunctionEvidence:
    start: int
    name: str
    score: int
    reasons: Sequence[str]
    apis: Sequence[tuple[str, str | None]]  # (name, family)
    callers: Sequence[tuple[int, str]]
    callees: Sequence[tuple[int, str]]
    strings: Sequence[str]
    code: str | None
    code_kind: Literal["pseudo_c", "asm"] | None


@dataclass(frozen=True)
class BundleInput:
    name: str
    sha256: str
    size: int
    format: str
    bits: int
    is_dll: bool
    entry_point: int | None
    compile_time: str | None
    signature: str
    packer: str | None
    score: int
    band: str
    facts: Sequence[Fact]
    functions: Sequence[FunctionEvidence]  # most suspicious first
    iocs: Sequence[tuple[str, str]]  # (type, value)
    imports: Mapping[str, Sequence[str]]  # family -> API names
    sections: Sequence[tuple[str, str, float]]  # (name, permissions, entropy)
    notes: Sequence[tuple[int, str, str]]  # (address, "name" | "comment", text)


@dataclass(frozen=True)
class Bundle:
    doc: dict[str, Any]
    text: str  # the preview and the message sent
    hash: str
    omitted: dict[str, int]
    fact_ids: frozenset[str]  # what a report may cite
    functions: frozenset[int]
    iocs: frozenset[str]


def _hex(value: int) -> str:
    return f"{value:#x}"


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _finding(fact: Fact) -> dict[str, Any]:
    evidence = []
    for e in fact.evidence[:MAX_EVIDENCE]:
        item: dict[str, Any] = {"detail": _cut(e.detail, MAX_STRING_CHARS)}
        if e.rva is not None:
            item["rva"] = _hex(e.rva)
        elif e.offset is not None:
            item["offset"] = _hex(e.offset)
        evidence.append(item)
    out: dict[str, Any] = {
        "id": fact.id,
        "kind": fact.kind,
        "severity": fact.severity,
        "title": _cut(fact.title, 200),
    }
    if fact.mitre:
        out["mitre"] = list(fact.mitre)
    out["evidence"] = evidence
    return out


def _function(fn: FunctionEvidence) -> dict[str, Any]:
    out: dict[str, Any] = {"addr": _hex(fn.start), "name": fn.name, "score": fn.score}
    if fn.reasons:
        out["why_ranked"] = [_cut(r, 200) for r in fn.reasons[:5]]
    out["apis"] = [
        {"name": name, "family": family} if family else {"name": name} for name, family in fn.apis
    ]
    for key, items in (("callers", fn.callers), ("callees", fn.callees)):
        out[key] = [{"addr": _hex(a), "name": n} for a, n in items[:MAX_NEIGHBOURS]]
    if fn.strings:
        out["strings"] = [_cut(s, MAX_STRING_CHARS) for s in fn.strings[:MAX_STRINGS]]
    return out


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=1)


def build_bundle(data: BundleInput, budget_chars: int = 24_000) -> Bundle:
    """Sample, findings and the function table always go in; code fills what room is left."""
    facts = sorted(data.facts, key=lambda f: (_SEVERITY[f.severity], f.kind, f.source_id))
    functions = list(data.functions)
    doc: dict[str, Any] = {
        "sample": {
            # the file name only: a folder path can carry a user or case name
            "name": PureWindowsPath(data.name).name,
            "sha256": data.sha256,
            "size": data.size,
            "format": data.format,
            "bits": data.bits,
            "is_dll": data.is_dll,
            "entry_point": _hex(data.entry_point) if data.entry_point is not None else None,
            "compile_time": data.compile_time,
            "signature": data.signature,
            "packer": data.packer,
            "risk_score": data.score,
            "risk_band": data.band,
        },
        "findings": [_finding(f) for f in facts[:MAX_FINDINGS]],
        "functions": [_function(f) for f in functions[:MAX_FUNCTIONS]],
        "iocs": [{"type": t, "value": _cut(v, 200)} for t, v in data.iocs[:MAX_IOCS]],
        "sensitive_imports": {family: list(apis) for family, apis in data.imports.items()},
        "sections": [{"name": n, "perm": p, "entropy": round(e, 2)} for n, p, e in data.sections],
        "analyst_notes": [
            {"addr": _hex(a), "kind": k, "text": _cut(t, 200)} for a, k, t in data.notes[:MAX_NOTES]
        ],
    }
    omitted = {
        "findings": max(0, len(facts) - MAX_FINDINGS),
        "functions": max(0, len(functions) - MAX_FUNCTIONS),
        "code": 0,
        "iocs": max(0, len(data.iocs) - MAX_IOCS),
    }
    doc["omitted"] = omitted
    used = len(_dump(doc))
    room = True
    for fn, row in zip(functions[:MAX_FUNCTIONS], doc["functions"], strict=True):
        if not fn.code:
            continue
        code = fn.code if len(fn.code) <= MAX_CODE_CHARS else fn.code[:MAX_CODE_CHARS] + _CUT
        cost = len(code) + 60
        # rank order: once one block does not fit, lower-ranked ones are not squeezed in
        if room and used + cost <= budget_chars:
            row["code_kind"] = fn.code_kind
            row["code"] = code
            used += cost
        else:
            room = False
            omitted["code"] += 1
    text = _dump(doc)
    return Bundle(
        doc=doc,
        text=text,
        hash=hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
        omitted=omitted,
        fact_ids=frozenset(f["id"] for f in doc["findings"]),
        functions=frozenset(fn.start for fn in functions[:MAX_FUNCTIONS]),
        iocs=frozenset(v for _, v in data.iocs[:MAX_IOCS]),
    )
