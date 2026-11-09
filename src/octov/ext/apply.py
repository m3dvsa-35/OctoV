"""Merge engine results into a sample's analysis and re-run the dependent core analyzers."""

from __future__ import annotations

from typing import Any

from octov.core.analysis.pipeline import AnalysisContext, Pipeline
from octov.core.analysis.strings import FoundString
from octov.ext.capa import capa_facts, parse_capa
from octov.ext.floss import floss_facts, merge_strings, parse_floss


def image_span(ctx: AnalysisContext) -> tuple[int, int]:
    """(image base, image size) used to turn engine VAs into RVAs; raw blobs map 1:1."""
    if ctx.report is None:
        return 0, len(ctx.data)
    end = max(
        (s.virtual_address + max(s.virtual_size, s.raw_size) for s in ctx.report.sections),
        default=len(ctx.data),
    )
    return ctx.report.image_base, end


def apply_floss(ctx: AnalysisContext, pipeline: Pipeline, doc: dict[str, Any]) -> None:
    base, size = image_span(ctx)
    recovered = parse_floss(doc, base, size)
    static: list[FoundString] = [s for s in ctx.results.get("strings", []) if s.origin == "static"]
    ctx.results["recovered_strings"] = recovered
    ctx.results["strings"] = merge_strings(static, recovered)
    pipeline.rerun(["iocs"], ctx)
    hidden = [i for i in ctx.results.get("iocs", []) if i.offsets and max(i.offsets) < 0]
    ctx.add(floss_facts(recovered, hidden))


def apply_capa(ctx: AnalysisContext, pipeline: Pipeline, doc: dict[str, Any]) -> None:
    """Call after the slow lane finished, so matches attach to discovered functions."""
    base, size = image_span(ctx)
    matches = parse_capa(doc, base, size)
    ctx.results["capa"] = matches
    ctx.add(capa_facts(matches, ctx.index))
    if ctx.functions:
        pipeline.rerun(["naming", "ranking"], ctx)
