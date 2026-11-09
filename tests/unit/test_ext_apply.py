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
