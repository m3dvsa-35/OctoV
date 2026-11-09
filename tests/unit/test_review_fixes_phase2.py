"""Regression tests for the Phase 2 final-review findings (Important 1-4, Minor 4 re-graded)."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest

from octov.app import api as api_mod
from octov.core.analysis.analyzers import Iocs
from octov.core.analysis.iocs import Ioc, ioc_fact_id
from octov.core.analysis.pipeline import AnalysisContext
from octov.core.analysis.strings import FoundString, classify
from octov.ext import runner
from octov.ext.floss import floss_facts
from octov.ext.queue import EngineQueue
from octov.ext.runner import EngineError
from tests.unit.test_ext_api import _api, _settled
from tests.unit.test_triage_api import _suspicious

# -- Important 1: reopen while the old engine job is still finishing -----------------


def test_queue_accepts_same_sha_for_a_new_owner() -> None:
    q = EngineQueue("rf1")
    release = threading.Event()
    ran: list[str] = []
    old, new = object(), object()

    def first(cancel: threading.Event) -> None:
        ran.append("old")
        release.wait(5)

    assert q.submit("a" * 64, first, owner=old)
    end = time.monotonic() + 5
    while ran != ["old"]:
        assert time.monotonic() < end
        time.sleep(0.01)
    assert not q.submit("a" * 64, first, owner=old)  # same sample: duplicate
    assert q.submit("a" * 64, lambda c: ran.append("new"), owner=new)  # reopened sample
    release.set()
    end = time.monotonic() + 5
    while ran != ["old", "new"]:
        assert time.monotonic() < end
        time.sleep(0.01)


def test_reopen_while_capa_result_is_applied(
    tmp_path: Path, engines: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    engines["ready"] = {"capa"}
    gate = threading.Event()
    calls: list[int] = []
    real = api_mod.apply_capa

    def slow_first(ctx: AnalysisContext, pipeline: Any, doc: dict[str, Any]) -> None:
        calls.append(1)
        if len(calls) == 1:
            gate.wait(20)  # the old sample's result is still being applied
        real(ctx, pipeline, doc)

    monkeypatch.setattr(api_mod, "apply_capa", slow_first)
    api = _api(tmp_path)
    path = str(_suspicious(tmp_path))
    sha = api.open_sample(path)["sha256"]
    end = time.monotonic() + 20
    while not calls:
        assert time.monotonic() < end
        time.sleep(0.05)
    api.close_sample(sha)
    api._cache_dir = tmp_path / "cache2"  # force a real run for the reopened sample
    api.open_sample(path)
    try:
        assert _settled(api, sha, timeout=30)["capa"]["state"] == "done"
    finally:
        gate.set()


# -- Important 2: mixed static + recovered IOC keeps its fact id ---------------------


def test_ioc_fact_id_ignores_recovered_offsets() -> None:
    assert ioc_fact_id(Ioc("domain", "evil.example.com", (-1, 0x200), None)) == "ioc:domain:0x200"
    assert ioc_fact_id(Ioc("domain", "evil.example.com", (-1,), None)) == "ioc:domain:-0x1"


def test_mixed_ioc_keeps_fact_and_id_after_floss() -> None:
    static = FoundString("http://evil.example.com/a", "ascii", 0x200, 0x2200, ".data", "url")
    rec_value = "http://evil.example.com/b"
    recovered = FoundString(
        rec_value, "ascii", -1, 0x1000, None, classify(rec_value), "stack", 0x1000
    )
    ctx = AnalysisContext(b"", None, 64, [])
    ctx.results["strings"] = [static, recovered]
    Iocs().run(ctx)
    domain = next(f for f in ctx.facts if f.kind == "ioc" and f.source_id == "domain")
    assert domain.id == "ioc:domain:0x200"
    assert all(e.offset is not None and e.offset >= 0 for e in domain.evidence)


# -- Important 3: the file changed on disk after it was opened ------------------------


def test_file_changed_on_disk_is_not_analysed_or_cached(
    tmp_path: Path, engines: dict[str, Any]
) -> None:
    engines["ready"] = {"capa"}
    api = _api(tmp_path)
    api.set_settings({"extensions_auto_run": {"capa": False, "floss": False}})
    path = _suspicious(tmp_path)
    sha = api.open_sample(str(path))["sha256"]
    path.write_bytes(path.read_bytes() + b"rebuilt")
    api.run_extension(sha, "capa")
    jobs = _settled(api, sha)
    assert (jobs["capa"]["state"], jobs["capa"]["error"]) == ("failed", "file changed on disk")
    assert engines["started"]["capa"] == 0
    assert not list((tmp_path / "cache").rglob("*.gz"))


# -- Important 4: every failure ends in a terminal state ------------------------------


def test_runner_os_error_becomes_engine_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(max_memory_mb: int) -> None:
        raise OSError(5, "CreateJobObjectW failed")

    monkeypatch.setattr(runner, "_Job", broken)
    with pytest.raises(EngineError) as err:
        runner.run_engine(["x"], timeout_s=1, max_memory_mb=10, cancel=threading.Event())
    assert err.value.kind == "crash" and "CreateJobObjectW" in err.value.reason


def test_unexpected_exception_in_apply_ends_failed(
    tmp_path: Path, engines: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    engines["ready"] = {"floss"}

    def boom(*args: Any) -> None:
        raise RuntimeError("adapter bug")

    monkeypatch.setattr(api_mod, "apply_floss", boom)
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    jobs = _settled(api, sha)
    assert jobs["floss"]["state"] == "failed"
    assert "adapter bug" in jobs["floss"]["error"]


# -- Minor 4 (re-graded): every FLOSS fact carries an offset or RVA -------------------


def test_floss_facts_always_locate_their_evidence() -> None:
    recovered = [
        FoundString(f"value {i}", "ascii", -1, None, None, None, "decoded", None) for i in range(5)
    ]
    hidden = [Ioc("url", "http://x.example/a", (-1,), None)]
    for fact in floss_facts(recovered, hidden):
        assert all(e.offset is not None or e.rva is not None for e in fact.evidence), fact.kind
