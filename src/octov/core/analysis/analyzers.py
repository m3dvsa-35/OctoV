"""Concrete analyzers wiring the analysis modules into the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field

from octov.core.analysis.carve import carve_payloads, payload_facts
from octov.core.analysis.crypto import find_crypto
from octov.core.analysis.facts import Evidence, Fact, facts_from_findings, facts_from_indicators
from octov.core.analysis.iocs import build_iocs
from octov.core.analysis.naming import suggest_name
from octov.core.analysis.packer import packer_fact, packer_verdict
from octov.core.analysis.pipeline import AnalysisContext, Analyzer
from octov.core.analysis.scoring import rank_functions
from octov.core.analysis.strings import extract_strings
from octov.core.analysis.xrefs import XrefIndex
from octov.core.static.cfg import FunctionIndex, discover_from, discover_functions
from octov.core.static.disasm import Disassembler, ImageView, RawView

# IOC kinds worth surfacing as facts (info severity: shown, never scored).
FACT_IOC_TYPES = frozenset({"url", "ipv4", "ipv6", "domain", "email", "mutex", "wallet", "command"})


@dataclass
class _Base:
    id: str
    cost: str = "fast"
    depends_on: tuple[str, ...] = field(default_factory=tuple)
    pe_only: bool = False


class PeIndicators(_Base):
    def __init__(self) -> None:
        super().__init__("pe_indicators", pe_only=True)

    def run(self, ctx: AnalysisContext) -> None:
        assert ctx.report is not None
        ctx.add(facts_from_indicators(ctx.report))


class Rules(_Base):
    def __init__(self) -> None:
        super().__init__("rules")

    def run(self, ctx: AnalysisContext) -> None:
        ctx.add(facts_from_findings(ctx.findings))


class Strings(_Base):
    def __init__(self) -> None:
        super().__init__("strings")

    def run(self, ctx: AnalysisContext) -> None:
        ctx.results["strings"] = extract_strings(ctx.data, ctx.report)


class Iocs(_Base):
    def __init__(self) -> None:
        super().__init__("iocs", depends_on=("strings",))

    def run(self, ctx: AnalysisContext) -> None:
        iocs = build_iocs(ctx.results.get("strings", []))
        ctx.results["iocs"] = iocs
        ctx.add(
            Fact(
                kind="ioc",
                source_id=i.type,
                severity="info",
                title=f"{i.type}: {i.value}",
                evidence=tuple(Evidence(i.value, offset=o, value=i.value) for o in i.offsets),
                explain_key="fact.ioc",
            )
            for i in iocs
            if i.type in FACT_IOC_TYPES and i.benign_hint is None
        )


class Crypto(_Base):
    def __init__(self) -> None:
        super().__init__("crypto")

    def run(self, ctx: AnalysisContext) -> None:
        ctx.add(find_crypto(ctx.data, ctx.report))


class Carve(_Base):
    def __init__(self) -> None:
        super().__init__("carve")

    def run(self, ctx: AnalysisContext) -> None:
        payloads = carve_payloads(ctx.data, ctx.report)
        ctx.results["payloads"] = payloads
        ctx.add(payload_facts(payloads))


class Packer(_Base):
    def __init__(self) -> None:
        super().__init__("packer", pe_only=True)

    def run(self, ctx: AnalysisContext) -> None:
        assert ctx.report is not None
        verdict = packer_verdict(ctx.report)
        ctx.results["packer"] = verdict
        fact = packer_fact(ctx.report, verdict)
        if fact is not None:
            ctx.add([fact])


class Functions(_Base):
    def __init__(self) -> None:
        super().__init__("functions", cost="slow")

    def run(self, ctx: AnalysisContext) -> None:
        if ctx.report is not None:
            dis = Disassembler(ImageView(ctx.data, ctx.report))
            functions = discover_functions(dis, ctx.report)
        else:
            functions = discover_from(Disassembler(RawView(ctx.data, bits=ctx.bits)), [0])
        ctx.functions = functions
        ctx.index = FunctionIndex(functions)


class Xrefs(_Base):
    def __init__(self) -> None:
        super().__init__("xrefs", cost="slow", depends_on=("functions",))

    def run(self, ctx: AnalysisContext) -> None:
        imports = ctx.report.import_addresses if ctx.report is not None else {}
        ctx.results["xrefs"] = XrefIndex.build(ctx.functions, imports)


class Naming(_Base):
    def __init__(self) -> None:
        super().__init__("naming", cost="slow", depends_on=("xrefs",))

    def run(self, ctx: AnalysisContext) -> None:
        xrefs: XrefIndex = ctx.results["xrefs"]
        names = {}
        for start in ctx.functions:
            name = suggest_name(start, xrefs.imports_called(start))
            if name:
                names[start] = name
        ctx.results["names"] = names


class Ranking(_Base):
    def __init__(self) -> None:
        super().__init__("ranking", cost="slow", depends_on=("naming", "strings", "crypto"))

    def run(self, ctx: AnalysisContext) -> None:
        ctx.results["ranking"] = rank_functions(
            ctx.functions,
            ctx.results["xrefs"],
            ctx.facts,
            ctx.results.get("strings", []),
            ctx.results.get("names", {}),
        )


def default_analyzers() -> list[Analyzer]:
    return [
        PeIndicators(),
        Rules(),
        Strings(),
        Iocs(),
        Crypto(),
        Carve(),
        Packer(),
        Functions(),
        Xrefs(),
        Naming(),
        Ranking(),
    ]
