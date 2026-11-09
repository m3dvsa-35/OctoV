"""Facts: the single result model of the analysis pipeline.

Every automatic result (indicator, rule match, IOC, crypto constant, payload,
packer verdict, ...) is a :class:`Fact` with at least one evidence location, a
stable ID (so analyst verdicts survive re-analysis) and an explanation key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from octov.core.static.pe_parser import Indicator, PEReport, Severity, normalize_api
from octov.core.static.rules import Finding


@dataclass(frozen=True)
class Evidence:
    detail: str
    offset: int | None = None
    rva: int | None = None
    type: str | None = None
    value: str | None = None


@dataclass(frozen=True)
class Fact:
    kind: str
    source_id: str
    severity: Severity
    title: str
    evidence: tuple[Evidence, ...]
    mitre: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    confidence: float = 1.0
    explain_key: str | None = None

    @property
    def primary(self) -> str:
        rvas = [e.rva for e in self.evidence if e.rva is not None]
        if rvas:
            return hex(min(rvas))
        offsets = [e.offset for e in self.evidence if e.offset is not None]
        if offsets:
            return hex(min(offsets))
        return next((e.value for e in self.evidence if e.value), "")

    @property
    def id(self) -> str:
        """Stable across re-analysis: ``<kind>:<source_id>:<primary location>``."""
        return f"{self.kind}:{self.source_id}:{self.primary}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "source_id": self.source_id,
            "severity": self.severity,
            "title": self.title,
            "mitre": list(self.mitre),
            "tags": list(self.tags),
            "confidence": self.confidence,
            "explain_key": self.explain_key,
            "evidence": [
                {
                    "detail": e.detail,
                    "offset": e.offset,
                    "rva": e.rva,
                    "type": e.type,
                    "value": e.value,
                }
                for e in self.evidence
            ],
        }


def _indicator_evidence(ind: Indicator, report: PEReport) -> tuple[Evidence, ...]:
    ev = ind.evidence
    sections = {s.name: s for s in report.sections}
    if "section" in ev and ev["section"] in sections:
        sec = sections[ev["section"]]
        return (Evidence(f"section {sec.name}", offset=sec.raw_offset, rva=sec.virtual_address),)
    if "apis" in ev:
        wanted = {normalize_api(a) for a in ev["apis"]}
        out = tuple(
            Evidence(f"import {name}", rva=rva, type="import", value=name)
            for rva, name in sorted(report.import_addresses.items())
            if normalize_api(name.split("!", 1)[-1]) in wanted
        )
        if out:
            return out
    if "entry_point" in ev:
        return (Evidence("entry point", rva=int(str(ev["entry_point"]), 16)),)
    if "offset" in ev:
        return (Evidence("overlay", offset=int(ev["offset"])),)
    # Header-level facts (no imports, timestamp): point at the start of the image.
    return (Evidence("PE header", offset=0, rva=0),)


def facts_from_indicators(report: PEReport) -> list[Fact]:
    return [
        Fact(
            kind="indicator",
            source_id=ind.id,
            severity=ind.severity,
            title=ind.description,
            evidence=_indicator_evidence(ind, report),
            mitre=tuple(ind.mitre),
            explain_key=f"ind.{ind.id}",
        )
        for ind in report.indicators
    ]


def facts_from_findings(findings: list[Finding]) -> list[Fact]:
    facts = []
    for f in findings:
        evidence = tuple(
            Evidence(m.detail, offset=m.offset, rva=m.rva, type=m.type, value=m.value)
            for m in f.matches
        )
        if not any(e.offset is not None or e.rva is not None for e in evidence):
            # Import-only matches: anchor at the PE header so every fact has a location.
            evidence += (Evidence("matched by import table", offset=0, rva=0),)
        facts.append(
            Fact(
                kind="rule",
                source_id=f.rule_id,
                severity=f.severity,
                title=f.name,
                evidence=evidence,
                mitre=tuple(f.mitre),
                explain_key="fact.rule",
            )
        )
    return facts
