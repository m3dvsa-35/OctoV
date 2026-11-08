"""One packed / not-packed verdict with reasons, combining individual PE signals."""

from __future__ import annotations

from dataclasses import dataclass

from octov.core.analysis.facts import Evidence, Fact
from octov.core.static.pe_parser import PACKER_SECTION_NAMES, PEReport, normalize_api

ENTRY_ENTROPY = 7.0
FEW_IMPORTS = 10
_LOADERS = {"LoadLibrary", "LoadLibraryEx", "LdrLoadDll", "GetModuleHandle"}
_RESOLVERS = {"GetProcAddress", "LdrGetProcedureAddress"}


@dataclass(frozen=True)
class PackerVerdict:
    packed: bool
    confidence: float
    packer: str | None
    reasons: tuple[str, ...]


def packer_verdict(report: PEReport) -> PackerVerdict:
    reasons: list[str] = []
    packer = next(
        (PACKER_SECTION_NAMES[s.name] for s in report.sections if s.name in PACKER_SECTION_NAMES),
        None,
    )
    if packer:
        reasons.append(f"section names typical of {packer}")
    entry = next((s for s in report.sections if s.contains_rva(report.entry_point)), None)
    if entry is not None and entry.raw_size and entry.entropy >= ENTRY_ENTROPY:
        reasons.append(f"entry section {entry.name} has entropy {entry.entropy:.2f}")
    funcs = {normalize_api(f) for fs in report.imports.values() for f in fs}
    if report.import_count <= FEW_IMPORTS and funcs & _LOADERS and funcs & _RESOLVERS:
        reasons.append(f"only {report.import_count} imports incl. a loader/resolver pair")
    if any(s.writable and s.executable for s in report.sections):
        reasons.append("writable and executable section")
    if any(
        s.virtual_size >= 0x1000 and (s.raw_size == 0 or s.virtual_size > s.raw_size * 10)
        for s in report.sections
    ):
        reasons.append("section reserves far more memory than it stores (unpack target)")
    packed = len(reasons) >= 2
    return PackerVerdict(
        packed=packed,
        confidence=round(min(1.0, len(reasons) / 4), 2) if packed else 0.0,
        packer=packer if packed else None,
        reasons=tuple(reasons),
    )


def packer_fact(report: PEReport, verdict: PackerVerdict) -> Fact | None:
    if not verdict.packed:
        return None
    return Fact(
        kind="packer",
        source_id=verdict.packer or "generic",
        severity="medium",
        title=f"Packed with {verdict.packer}" if verdict.packer else "Likely packed or encrypted",
        evidence=(Evidence("entry point", rva=report.entry_point),)
        + tuple(Evidence(r) for r in verdict.reasons),
        mitre=("T1027.002",),
        confidence=verdict.confidence,
        explain_key="fact.packer",
    )
