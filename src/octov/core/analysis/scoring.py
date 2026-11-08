"""Transparent risk score and suspicious-function ranking.

Both are additive and list their reasons, so an analyst can see exactly why a
sample scored 72 or why a function is at the top of the list.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from octov.core.analysis.facts import Fact
from octov.core.analysis.iocs import IOC_TYPES
from octov.core.analysis.naming import API_FAMILIES
from octov.core.analysis.strings import FoundString
from octov.core.analysis.xrefs import XrefIndex
from octov.core.static.cfg import Function, FunctionIndex
from octov.core.static.pe_parser import normalize_api

SEVERITY_WEIGHT = {"high": 30, "medium": 12, "low": 4, "info": 0}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
IGNORED_VERDICTS = frozenset({"false_positive", "benign"})
SUSPICIOUS_FAMILIES = frozenset(
    {"thread_inject", "crypto", "net_http", "net_socket", "registry", "service", "anti_debug"}
)
TOP_FUNCTIONS = 20
_FAMILY_OF = {api: fam for fam, apis in API_FAMILIES.items() for api in apis}


@dataclass(frozen=True)
class RiskScore:
    score: int
    band: Literal["low", "medium", "high"]
    contributions: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class RankedFunction:
    start: int
    name: str
    score: int
    reasons: tuple[str, ...]


def _signal(fact: Fact) -> tuple[str, ...]:
    """Facts with the same signal are one piece of evidence (crypto tables are one signal)."""
    return (fact.kind,) if fact.kind == "crypto_constant" else (fact.kind, fact.source_id)


def risk_score(facts: Sequence[Fact], verdicts: Mapping[str, str]) -> RiskScore:
    """Additive score; each signal counts once (its strongest fact), repeats are listed at 0.

    Calibrated on the System32 sweep: an asset DLL with 20 compressed blobs or a kernel with
    7 inflated sections is one weak signal, not 20 or 7.
    """
    contributions: list[tuple[str, int]] = []
    counted: set[tuple[str, ...]] = set()
    weighted = sorted(facts, key=lambda f: -round(SEVERITY_WEIGHT[f.severity] * f.confidence))
    for fact in weighted:
        points = 0
        if verdicts.get(fact.id) not in IGNORED_VERDICTS and _signal(fact) not in counted:
            points = round(SEVERITY_WEIGHT[fact.severity] * fact.confidence)
            counted.add(_signal(fact))
        contributions.append((fact.id, points))
    contributions.sort(key=lambda c: -c[1])
    score = min(100, sum(p for _, p in contributions))
    band: Literal["low", "medium", "high"] = (
        "high" if score >= 60 else "medium" if score >= 30 else "low"
    )
    return RiskScore(score, band, tuple(contributions))


def rank_functions(
    functions: Mapping[int, Function],
    xrefs: XrefIndex,
    facts: Sequence[Fact],
    strings: Sequence[FoundString],
    names: Mapping[int, str],
) -> list[RankedFunction]:
    index = FunctionIndex(dict(functions))
    points: dict[int, int] = defaultdict(int)
    reasons: dict[int, list[str]] = defaultdict(list)

    for fact in facts:
        rank = SEVERITY_RANK[fact.severity]
        hit: set[int] = set()
        for ev in fact.evidence:
            if ev.rva is None:
                continue
            owners = [index.lookup(ev.rva)]
            # Data evidence (crypto tables, IOC strings) counts for the code that reads it.
            owners += [index.lookup(x.src) for x in xrefs.to(ev.rva)]
            hit |= {fn.start for fn in owners if fn is not None}
        for start in hit:
            points[start] += 10 * rank if fact.kind != "crypto_constant" else 4
            reasons[start].append(f"{fact.source_id}: {fact.title} ({fact.severity})")

    for start in functions:
        families = Counter(
            _FAMILY_OF.get(normalize_api(name.rsplit("!", 1)[-1]))
            for name in xrefs.imports_called(start)
        )
        for family, count in families.items():
            if family in SUSPICIOUS_FAMILIES:
                points[start] += 5 * count
                reasons[start].append(f"calls {count} {family} API(s)")

    for s in strings:
        if s.rva is None or s.category not in IOC_TYPES:
            continue
        for x in xrefs.to(s.rva):
            if x.func is not None and x.func in functions:
                points[x.func] += 4
                reasons[x.func].append(f"references {s.category} {s.value}")

    ranked = [
        RankedFunction(start, names.get(start, f"sub_{start:x}"), score, tuple(reasons[start]))
        for start, score in points.items()
        if score > 0 and start in functions
    ]
    ranked.sort(key=lambda r: (-r.score, r.start))
    return ranked[:TOP_FUNCTIONS]
