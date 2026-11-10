"""Regression tests for the Phase 3 (Ghidra decompiler) final-review findings."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from octov.app import api as api_mod
from octov.cli.main import main
from octov.core.config import GhidraConfig
from octov.ext import ExtensionStatus
from octov.ext.ghidra import manager as manager_mod
from octov.ext.ghidra.manager import GhidraManager, GhidraWorker, WorkerCommand, worker_command
from octov.ext.ghidra.protocol import GhidraError
from octov.ext.ghidra.worker import ANALYSED_MARKER, PROGRAM, project_usable
from octov.ext.runner import _Job
from tests.unit.test_ghidra_manager import A, States, _ghidra_ready
from tests.unit.test_triage_api import _suspicious

READY = ExtensionStatus("ghidra", True, True, "12.2", "25.0.1", None, "", None)


# -- 1: a project whose analysis never finished must not be reused ---------------------


def test_project_without_finished_analysis_is_not_usable(tmp_path: Path) -> None:
    assert not project_usable(tmp_path)
    (tmp_path / f"{PROGRAM}.gpr").write_bytes(b"")
    assert not project_usable(tmp_path)  # imported, but the worker died while analysing
    (tmp_path / ANALYSED_MARKER).write_bytes(b"")
    assert project_usable(tmp_path)


@pytest.mark.skipif(not _ghidra_ready(), reason="needs pyghidra, Ghidra 12.x and a JDK >= 21")
def test_real_worker_reanalyses_project_left_mid_analysis(tmp_path: Path) -> None:
    cfg = GhidraConfig()
    data = _suspicious(tmp_path).read_bytes()
    root = tmp_path / "projects"
    st = States()
    mgr = GhidraManager(cfg, lambda: worker_command(cfg), root)
    try:
        mgr.ensure(A, data, st.on(A))
        st.wait(A, "done", 300)
        assert (root / A / ANALYSED_MARKER).is_file()
        mgr.close(A)
        (root / A / ANALYSED_MARKER).unlink()  # as if the worker had died during analysis
        mgr.ensure(A, data, st.on(A))
        deadline = time.monotonic() + 300
        while st.events.count((A, "done", None)) < 2 and time.monotonic() < deadline:
            assert st.last(A) != "failed", st.events
            time.sleep(0.2)
        worker = mgr.worker(A)
        assert worker is not None and worker.analysed
        assert (root / A / ANALYSED_MARKER).is_file()
    finally:
        mgr.shutdown_all()


# -- 2: the triage CLI never starts the decompiler -------------------------------------


@pytest.mark.parametrize("extra", [["--no-ext"], []])
def test_triage_cli_never_starts_ghidra(
    extra: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    started: list[str] = []
    monkeypatch.setattr(api_mod, "ghidra_status", lambda cfg: READY)
    monkeypatch.setattr(
        GhidraManager, "ensure", lambda self, sha, data, on_state: started.append(sha)
    )
    assert main(["triage", str(_suspicious(tmp_path)), *extra]) == 0
    capsys.readouterr()
    assert started == []


# -- 4: a worker that never reads its input cannot block forever ------------------------


def test_open_times_out_when_the_worker_never_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(manager_mod, "_START_GRACE_S", 0.0)
    deaf = WorkerCommand([sys.executable, "-c", "import time; time.sleep(120)"])
    data = b"MZ" + b"\0" * (4 << 20)  # far more than a pipe buffer holds
    worker = GhidraWorker(A, data, GhidraConfig(analysis_timeout_s=1), deaf, tmp_path)
    errors: list[GhidraError] = []

    def start() -> None:
        try:
            worker.start()
        except GhidraError as exc:
            errors.append(exc)

    thread = threading.Thread(target=start, daemon=True)
    thread.start()
    thread.join(15)
    try:
        assert not thread.is_alive(), "open is stuck writing to a worker that does not read"
        assert [e.kind for e in errors] == ["timeout"]
        assert not worker.alive()
    finally:
        worker.stop()


# -- 5: closing a job from two threads closes its handle once ---------------------------


class _SlowKernel:
    def __init__(self) -> None:
        self.closed = 0
        self.terminated_after_close = 0

    def CloseHandle(self, handle: Any) -> int:  # noqa: N802 - Win32 name
        time.sleep(0.05)
        self.closed += 1
        return 1

    def TerminateJobObject(self, handle: Any, code: int) -> int:  # noqa: N802 - Win32 name
        if self.closed:
            self.terminated_after_close += 1
        return 1


@pytest.mark.skipif(sys.platform != "win32", reason="Job Objects are Windows-only")
def test_job_close_is_safe_from_two_threads() -> None:
    job = _Job(64)
    real, handle = job._k32, job.handle
    fake = _SlowKernel()
    job._k32 = fake
    try:
        threads = [threading.Thread(target=job.close) for _ in range(4)]
        threads += [threading.Thread(target=job.kill) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        job.kill()
        assert fake.closed == 1
        assert fake.terminated_after_close == 0  # never use a handle after closing it
        assert job.handle is None and job.peak_memory() == 0
    finally:
        from ctypes import wintypes

        real.CloseHandle(wintypes.HANDLE(handle))
