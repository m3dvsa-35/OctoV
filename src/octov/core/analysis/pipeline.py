"""Analyzer pipeline: fast analyzers run inline, slow ones in a background thread."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from octov.core.analysis.facts import Fact
from octov.core.static.cfg import Function, FunctionIndex
from octov.core.static.pe_parser import PEReport
from octov.core.static.rules import Finding

AnalyzerStatus = Literal["queued", "running", "done", "failed", "unavailable"]


@dataclass
class AnalysisContext:
    data: bytes
    report: PEReport | None
    bits: int
    findings: list[Finding]
    functions: dict[int, Function] = field(default_factory=dict)
    index: FunctionIndex | None = None
    results: dict[str, Any] = field(default_factory=dict)
    facts: list[Fact] = field(default_factory=list)
    _ids: set[str] = field(default_factory=set, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def add(self, facts: Iterable[Fact]) -> None:
        with self._lock:
            for fact in facts:
                if fact.id not in self._ids:
                    self._ids.add(fact.id)
                    self.facts.append(fact)


class Analyzer(Protocol):
    id: str
    cost: str  # "fast" | "slow"
    depends_on: tuple[str, ...]
    pe_only: bool

    def run(self, ctx: AnalysisContext) -> None: ...


def _ordered(analyzers: Sequence[Analyzer]) -> list[Analyzer]:
    by_id = {a.id: a for a in analyzers}
    done: list[Analyzer] = []
    state: dict[str, int] = {}

    def visit(a: Analyzer) -> None:
        if state.get(a.id) == 2:
            return
        if state.get(a.id) == 1:
            raise ValueError(f"cyclic analyzer dependency at {a.id}")
        state[a.id] = 1
        for dep in a.depends_on:
            if dep in by_id:
                visit(by_id[dep])
        state[a.id] = 2
        done.append(a)

    for a in analyzers:
        visit(a)
    return done


class Pipeline:
    def __init__(self, analyzers: Sequence[Analyzer]) -> None:
        self._analyzers = _ordered(analyzers)
        self._lock = threading.Lock()
        self._status: dict[str, dict[str, Any]] = {
            a.id: self._entry("queued") for a in self._analyzers
        }
        self._slow_done = threading.Event()

    @staticmethod
    def _entry(
        state: AnalyzerStatus,
        error: str | None = None,
        elapsed_s: float | None = None,
        cached: bool = False,
    ) -> dict[str, Any]:
        return {"state": state, "error": error, "elapsed_s": elapsed_s, "cached": cached}

    def _set(self, analyzer_id: str, state: AnalyzerStatus, error: str | None = None) -> None:
        with self._lock:
            self._status[analyzer_id] = self._entry(state, error)

    def set_state(
        self,
        analyzer_id: str,
        state: AnalyzerStatus,
        error: str | None = None,
        *,
        elapsed_s: float | None = None,
        cached: bool = False,
    ) -> None:
        """Status of a job run outside this pipeline (the capa / FLOSS extension lane)."""
        with self._lock:
            self._status[analyzer_id] = self._entry(state, error, elapsed_s, cached)

    def status(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self._status.items()}

    def _run_one(self, a: Analyzer, ctx: AnalysisContext) -> None:
        current = self.status()
        blocked = [
            d for d in a.depends_on if current.get(d, {}).get("state") in ("failed", "unavailable")
        ]
        if blocked:
            self._set(a.id, "unavailable", f"needs {', '.join(blocked)}")
            return
        if a.pe_only and ctx.report is None:
            self._set(a.id, "unavailable", "PE files only")
            return
        self._set(a.id, "running")
        try:
            a.run(ctx)
        except Exception as exc:  # reported, never fatal to the pipeline
            self._set(a.id, "failed", str(exc))
            return
        self._set(a.id, "done")

    def run_fast(self, ctx: AnalysisContext) -> None:
        for a in self._analyzers:
            if a.cost == "fast":
                self._run_one(a, ctx)

    def start_slow(self, ctx: AnalysisContext, on_done: Callable[[], None] | None = None) -> None:
        def work() -> None:
            for a in self._analyzers:
                if a.cost == "slow":
                    self._run_one(a, ctx)
            self._slow_done.set()
            if on_done is not None:
                on_done()

        threading.Thread(target=work, daemon=True, name="octov-analysis").start()

    def wait_slow(self, timeout: float | None = None) -> bool:
        """Block until the slow lane has finished (True) or ``timeout`` passed (False)."""
        return self._slow_done.wait(timeout)

    def rerun(self, ids: Sequence[str], ctx: AnalysisContext) -> None:
        """Run the named analyzers again, synchronously, in dependency order."""
        wanted = set(ids)
        for a in self._analyzers:
            if a.id in wanted:
                self._run_one(a, ctx)
