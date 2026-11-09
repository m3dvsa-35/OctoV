from __future__ import annotations

import threading
from dataclasses import dataclass, field

import pytest

from octov.core.analysis.facts import Evidence, Fact, facts_from_findings, facts_from_indicators
from octov.core.analysis.pipeline import AnalysisContext, Pipeline
from octov.core.static.analysis import analyze
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe


def _ctx(data: bytes | None = None, raw: bool = False) -> AnalysisContext:
    data = data if data is not None else build_pe()
    if raw:
        return AnalysisContext(data=data, report=None, bits=64, findings=[])
    result = analyze(data)
    return AnalysisContext(data=data, report=result.report, bits=64, findings=result.findings)


def test_fact_id_uses_lowest_rva() -> None:
    fact = Fact(
        kind="rule",
        source_id="EVA-001",
        severity="high",
        title="t",
        evidence=(Evidence("a", rva=0x2010), Evidence("b", rva=0x2000, offset=0x10)),
    )
    assert fact.id == "rule:EVA-001:0x2000"


def test_fact_id_falls_back_to_offset_then_value() -> None:
    by_offset = Fact("x", "S", "low", "t", (Evidence("a", offset=0x40), Evidence("b", offset=0x20)))
    assert by_offset.id == "x:S:0x20"
    by_value = Fact("ioc", "url", "low", "t", (Evidence("a", value="http://x.example"),))
    assert by_value.id == "ioc:url:http://x.example"


def test_fact_to_dict_is_json_friendly() -> None:
    d = Fact("x", "S", "low", "t", (Evidence("a", offset=1),), mitre=("T1055",)).to_dict()
    assert d["id"] == "x:S:0x1" and d["mitre"] == ["T1055"] and d["evidence"][0]["offset"] == 1


def test_indicator_and_finding_adapters_carry_locations() -> None:
    blob = b"\x00" * 16 + bytes.fromhex("4C8BD1B8180000000F05")
    data = build_pe(
        PESpec(
            sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".data", blob, DATA)],
            imports={"kernel32.dll": ["WriteProcessMemory", "CreateRemoteThread"]},
        )
    )
    result = analyze(data)
    facts = facts_from_indicators(result.report) + facts_from_findings(result.findings)
    kinds = {f.kind for f in facts}
    assert kinds == {"indicator", "rule"}
    injection = next(f for f in facts if f.source_id == "process_injection_apis")
    assert {e.rva for e in injection.evidence} == set(result.report.import_addresses)
    assert injection.explain_key == "ind.process_injection_apis"
    assert next(f for f in facts if f.source_id == "EVA-001").explain_key == "fact.rule"
    for fact in facts:
        assert any(e.offset is not None or e.rva is not None for e in fact.evidence), fact.id


@dataclass
class _Probe:
    id: str
    cost: str = "fast"
    depends_on: tuple[str, ...] = ()
    pe_only: bool = False
    fail: bool = False
    log: list[str] = field(default_factory=list)

    def run(self, ctx: AnalysisContext) -> None:
        self.log.append(self.id)
        if self.fail:
            raise RuntimeError(f"{self.id} broke")
        ctx.results[self.id] = True


def test_pipeline_runs_fast_in_dependency_order() -> None:
    log: list[str] = []
    a = _Probe("a", depends_on=("b",), log=log)
    b = _Probe("b", log=log)
    pipeline = Pipeline([a, b])
    pipeline.run_fast(_ctx())
    assert log == ["b", "a"]
    done = {"state": "done", "error": None, "elapsed_s": None, "cached": False}
    assert pipeline.status() == {"a": done, "b": done}


def test_slow_analyzers_report_status_and_errors() -> None:
    log: list[str] = []
    ok = _Probe("ok", cost="slow", log=log)
    bad = _Probe("bad", cost="slow", fail=True, log=log)
    after_bad = _Probe("after", cost="slow", depends_on=("bad",), log=log)
    pipeline = Pipeline([ok, bad, after_bad])
    assert pipeline.status()["ok"]["state"] == "queued"
    done = threading.Event()
    pipeline.start_slow(_ctx(), on_done=done.set)
    assert done.wait(10)
    status = pipeline.status()
    assert status["ok"]["state"] == "done"
    assert (status["bad"]["state"], status["bad"]["error"]) == ("failed", "bad broke")
    assert status["after"]["state"] == "unavailable"
    assert "after" not in log


def test_pe_only_analyzer_unavailable_for_raw() -> None:
    probe = _Probe("pe", pe_only=True)
    pipeline = Pipeline([probe])
    pipeline.run_fast(_ctx(b"\x90\xc3", raw=True))
    assert pipeline.status()["pe"]["state"] == "unavailable"
    assert probe.log == []


def test_context_add_dedupes_by_id() -> None:
    ctx = _ctx()
    fact = Fact("x", "S", "low", "t", (Evidence("a", offset=1),))
    ctx.add([fact, fact])
    assert ctx.facts == [fact]


def test_cyclic_dependencies_are_rejected() -> None:
    with pytest.raises(ValueError):
        Pipeline([_Probe("a", depends_on=("b",)), _Probe("b", depends_on=("a",))])


def test_status_has_elapsed_and_cached() -> None:
    pipeline = Pipeline([_Probe("a")])
    pipeline.set_state("capa", "running")
    assert pipeline.status()["capa"]["state"] == "running"
    pipeline.set_state("capa", "done", elapsed_s=12.5, cached=True)
    assert pipeline.status()["capa"] == {
        "state": "done",
        "error": None,
        "elapsed_s": 12.5,
        "cached": True,
    }


def test_rerun_respects_dependencies() -> None:
    log: list[str] = []
    a = _Probe("a", log=log)
    b = _Probe("b", depends_on=("a",), log=log)
    c = _Probe("c", cost="slow", depends_on=("b",), log=log)
    pipeline = Pipeline([a, b, c])
    ctx = _ctx()
    pipeline.rerun(["c", "a"], ctx)
    assert log == ["a", "c"]
    assert pipeline.status()["c"]["state"] == "done"


def test_wait_slow() -> None:
    pipeline = Pipeline([_Probe("s", cost="slow")])
    assert not pipeline.wait_slow(0.05)
    pipeline.start_slow(_ctx())
    assert pipeline.wait_slow(10)
