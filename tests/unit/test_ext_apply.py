from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from octov.core.analysis.analyzers import default_analyzers
from octov.core.analysis.pipeline import AnalysisContext, Pipeline
from octov.core.static.analysis import analyze
from octov.ext.apply import apply_capa, apply_floss, image_span
from tests.samples.builder import stack_string_pe
from tests.unit.test_triage_api import _suspicious

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
URL = "http://x.example/gate.php"


def _load(rel: str) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((FIXTURES / rel).read_text(encoding="utf-8"))
    return doc


def _analysed(data: bytes) -> tuple[AnalysisContext, Pipeline]:
    result = analyze(data)
    ctx = AnalysisContext(data, result.report, 64, result.findings)
    pipeline = Pipeline(default_analyzers())
    pipeline.run_fast(ctx)
    pipeline.start_slow(ctx)
    assert pipeline.wait_slow(30)
    return ctx, pipeline


def test_image_span() -> None:
    ctx, _ = _analysed(stack_string_pe(URL))
    base, size = image_span(ctx)
    assert base == 0x140000000 and size >= 0x2000
    raw = AnalysisContext(b"\x90" * 64, None, 64, [])
    assert image_span(raw) == (0, 64)


def test_apply_floss_adds_strings_iocs_and_hidden_ioc() -> None:
    ctx, pipeline = _analysed(stack_string_pe(URL))
    assert URL not in [s.value for s in ctx.results["strings"]]
    apply_floss(ctx, pipeline, _load("floss/synthetic_stack.json"))
    strings = {s.value: s for s in ctx.results["strings"]}
    assert strings[URL].origin == "stack"
    assert [s.value for s in ctx.results["recovered_strings"]] == [URL]
    assert URL in {i.value for i in ctx.results["iocs"]}
    kinds = [f.kind for f in ctx.facts]
    assert kinds.count("hidden_ioc") == 1
    # IOCs only seen in recovered strings are covered by hidden_ioc, not per-IOC facts
    assert not [f for f in ctx.facts if f.kind == "ioc" and f.primary == "-0x1"]
    assert pipeline.status()["iocs"]["state"] == "done"


def test_apply_capa_adds_facts_and_reranks(tmp_path: Path) -> None:
    ctx, pipeline = _analysed(_suspicious(tmp_path).read_bytes())
    apply_capa(ctx, pipeline, _load("capa/synthetic_injector.json"))
    caps = [f for f in ctx.facts if f.kind == "capability"]
    assert {f.source_id for f in caps} == {"create thread", "contain an embedded PE file"}
    thread = next(f for f in caps if f.source_id == "create thread")
    assert thread.evidence[0].rva == 0x1000  # attached to the containing function
    assert len(ctx.results["capa"]) == 2
    assert pipeline.status()["ranking"]["state"] == "done"


def _library_doc(ctx: AnalysisContext) -> dict[str, Any]:
    assert ctx.report is not None
    starts = sorted(s for s in ctx.functions if s != ctx.report.entry_point)
    return {
        "engine": "library",
        "version": 1,
        "sets": [{"file": "test.pat", "signatures": len(starts)}],
        "candidates": [
            {"rva": s, "set": "test.pat", "names": [f"lib_{s:x}"], "count": 1} for s in starts
        ],
    }


def test_apply_library_names_functions_and_reranks() -> None:
    from octov.core.analysis.library import LibraryMatch
    from octov.ext.apply import apply_library
    from tests.samples.builder import library_like_pe

    ctx, pipeline = _analysed(library_like_pe())
    doc = _library_doc(ctx)
    apply_library(ctx, pipeline, doc)
    first = doc["candidates"][0]["rva"]
    assert len(ctx.results["library"]) == 7
    assert ctx.results["library"][first] == LibraryMatch(first, f"lib_{first:x}", "test.pat")
    assert pipeline.status()["ranking"]["state"] == "done"


def test_library_results_change_neither_facts_nor_score() -> None:
    from octov.core.analysis.report import build_triage
    from octov.ext.apply import apply_library
    from tests.samples.builder import library_like_pe

    ctx, pipeline = _analysed(library_like_pe())
    before = build_triage(ctx, {}, {})
    assert before["library"] == {"functions": 0, "total": 8}
    apply_library(ctx, pipeline, _library_doc(ctx))
    after = build_triage(ctx, {}, {})
    assert after["library"] == {"functions": 7, "total": 8}
    assert after["score"] == before["score"]
    assert after["capabilities"] == before["capabilities"]
