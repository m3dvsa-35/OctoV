from __future__ import annotations

import os
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from octov.core.config import GhidraConfig
from octov.ext.ghidra import manager as manager_mod
from octov.ext.ghidra.manager import (
    GhidraManager,
    WorkerCommand,
    cleanup_projects,
    worker_command,
)
from octov.ext.ghidra.protocol import GhidraError

FAKE = str(Path(__file__).resolve().parents[1] / "fixtures" / "fake_ghidra_worker.py")
DATA = b"MZ" + b"\0" * 64
A, B, C = "a" * 64, "b" * 64, "c" * 64


def _factory(mode: str, log: Path | None = None) -> Callable[[], WorkerCommand]:
    argv = [sys.executable, FAKE, mode] + ([str(log)] if log else [])
    return lambda: WorkerCommand(argv)


class States:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, str | None]] = []
        self._cond = threading.Condition()

    def on(self, sha: str) -> Callable[[str, str | None, float], None]:
        def record(state: str, error: str | None, elapsed_s: float) -> None:
            with self._cond:
                self.events.append((sha, state, error))
                self._cond.notify_all()

        return record

    def last(self, sha: str) -> str | None:
        with self._cond:
            states = [s for who, s, _ in self.events if who == sha]
        return states[-1] if states else None

    def wait(self, sha: str, state: str, timeout: float = 20) -> None:
        with self._cond:
            ok = self._cond.wait_for(
                lambda: any(who == sha and s == state for who, s, _ in self.events), timeout
            )
        assert ok, f"{sha[:1]} never reached {state}: {self.events}"


def _manager(
    tmp_path: Path, mode: str = "ok", log: Path | None = None, **cfg: int
) -> tuple[GhidraManager, States]:
    mgr = GhidraManager(GhidraConfig(**cfg), _factory(mode, log), tmp_path / "projects")  # type: ignore[arg-type]
    return mgr, States()


def _ops(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8").split()


def test_decompile_applies_names(tmp_path: Path) -> None:
    mgr, st = _manager(tmp_path)
    try:
        mgr.ensure(A, DATA, st.on(A))
        st.wait(A, "done")
        reply = mgr.decompile(A, 0x1004, {0x1000: "inject_main"}, {})
        assert reply["entry_rva"] == 0x1000 and reply["name"] == "inject_main"
        assert mgr.functions(A) == [(0x1000, "FUN_00401000")]
        with pytest.raises(GhidraError) as err:
            mgr.decompile(A, 0x9999, {}, {})
        assert err.value.kind == "no_function"
        assert st.last(A) == "done"  # a bad address is not a worker failure
    finally:
        mgr.shutdown_all()


def test_decompile_before_ready_is_not_ready(tmp_path: Path) -> None:
    mgr, _ = _manager(tmp_path)
    with pytest.raises(GhidraError) as err:
        mgr.decompile(A, 0x1000, {}, {})
    assert err.value.kind == "not_ready"


def test_max_workers_queues_third(tmp_path: Path) -> None:
    mgr, st = _manager(tmp_path, max_workers=2)
    try:
        for sha in (A, B, C):
            mgr.ensure(sha, DATA, st.on(sha))
        st.wait(A, "done")
        st.wait(B, "done")
        time.sleep(0.5)
        assert st.last(C) == "queued"
        mgr.close(A)
        st.wait(C, "done")
    finally:
        mgr.shutdown_all()


def test_one_analysis_at_a_time(tmp_path: Path) -> None:
    mgr, st = _manager(tmp_path, "slow")
    try:
        mgr.ensure(A, DATA, st.on(A))
        mgr.ensure(B, DATA, st.on(B))
        st.wait(A, "done")
        st.wait(B, "done")
        assert st.events.index((B, "running", None)) > st.events.index((A, "done", None))
    finally:
        mgr.shutdown_all()


def test_worker_crash_restarts_once_then_fails(tmp_path: Path) -> None:
    log = tmp_path / "ops.log"
    mgr, st = _manager(tmp_path, "crash_on_decompile", log)
    try:
        mgr.ensure(A, DATA, st.on(A))
        st.wait(A, "done")
        with pytest.raises(GhidraError) as err:
            mgr.decompile(A, 0x1000, {}, {})
        assert err.value.kind == "crash"
        assert "3" in err.value.reason  # the exit code is the reason
        assert _ops(log) == ["open", "decompile", "open", "decompile"]
        assert st.last(A) == "failed"
        with pytest.raises(GhidraError) as again:
            mgr.decompile(A, 0x1000, {}, {})
        assert again.value.kind == "not_ready"
    finally:
        mgr.shutdown_all()


def test_request_timeout_kills_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(manager_mod, "_GRACE_S", 0.0)
    mgr, st = _manager(tmp_path, "hang", decompile_timeout_s=1)
    try:
        mgr.ensure(A, DATA, st.on(A))
        st.wait(A, "done")
        worker = mgr.worker(A)
        assert worker is not None and worker.alive()
        start = time.monotonic()
        with pytest.raises(GhidraError) as err:
            mgr.decompile(A, 0x1000, {}, {})
        assert err.value.kind == "timeout"
        assert time.monotonic() - start < 10
        assert not worker.alive()
        # one stuck function does not cost the sample its decompiler
        assert st.last(A) == "done"
        assert mgr.functions(A) == [(0x1000, "FUN_00401000")]
    finally:
        mgr.shutdown_all()


def test_close_stops_worker_and_frees_slot(tmp_path: Path) -> None:
    mgr, st = _manager(tmp_path, "slow", max_workers=1)
    try:
        mgr.ensure(A, DATA, st.on(A))
        mgr.ensure(B, DATA, st.on(B))
        st.wait(A, "running")
        deadline = time.monotonic() + 10
        while mgr.worker(A) is None and time.monotonic() < deadline:
            time.sleep(0.02)
        worker = mgr.worker(A)
        assert worker is not None
        mgr.close(A)  # while its open is still running
        st.wait(B, "done")
        assert not worker.alive()
        assert st.last(A) == "running"  # a closed sample reports nothing more
        assert mgr.worker(A) is None
    finally:
        mgr.shutdown_all()


def test_shutdown_all_stops_every_worker(tmp_path: Path) -> None:
    mgr, st = _manager(tmp_path)
    mgr.ensure(A, DATA, st.on(A))
    mgr.ensure(B, DATA, st.on(B))
    st.wait(A, "done")
    st.wait(B, "done")
    workers = [mgr.worker(A), mgr.worker(B)]
    mgr.shutdown_all()
    assert all(w is not None and not w.alive() for w in workers)


def test_idle_worker_is_reaped_and_restarted(tmp_path: Path) -> None:
    log = tmp_path / "ops.log"
    now = [1000.0]
    mgr = GhidraManager(
        GhidraConfig(idle_minutes=10), _factory("ok", log), tmp_path / "projects", lambda: now[0]
    )
    st = States()
    try:
        mgr.ensure(A, DATA, st.on(A))
        st.wait(A, "done")
        worker = mgr.worker(A)
        assert worker is not None
        now[0] += 599
        mgr.reap_idle()
        assert worker.alive()
        now[0] += 2
        mgr.reap_idle()
        assert not worker.alive() and mgr.worker(A) is None
        assert st.last(A) == "done"
        assert mgr.decompile(A, 0x1000, {}, {})["entry_rva"] == 0x1000
        assert _ops(log).count("open") == 2
    finally:
        mgr.shutdown_all()


def test_failed_sample_can_be_ensured_again(tmp_path: Path) -> None:
    command = [WorkerCommand([sys.executable, "-c", "import sys; sys.exit(7)"])]
    mgr = GhidraManager(GhidraConfig(), lambda: command[0], tmp_path / "projects")
    st = States()
    try:
        mgr.ensure(A, DATA, st.on(A))
        st.wait(A, "failed")
        assert any(s == "failed" and e and "7" in e for _, s, e in st.events)
        command[0] = WorkerCommand([sys.executable, FAKE, "ok"])
        mgr.ensure(A, DATA, st.on(A))
        st.wait(A, "done")
    finally:
        mgr.shutdown_all()


def test_open_touches_project_folder(tmp_path: Path) -> None:
    project = tmp_path / "projects" / A
    project.mkdir(parents=True)
    old = time.time() - 40 * 86400
    os.utime(project, (old, old))
    mgr, st = _manager(tmp_path)
    try:
        mgr.ensure(A, DATA, st.on(A))
        st.wait(A, "done")
        assert time.time() - project.stat().st_mtime < 3600
    finally:
        mgr.shutdown_all()


def test_cleanup_projects_keeps_recent(tmp_path: Path) -> None:
    now = time.time()
    old, recent = tmp_path / "old", tmp_path / "recent"
    for folder, days in ((old, 40), (recent, 5)):
        folder.mkdir()
        (folder / "sample.gpr").write_bytes(b"")
        os.utime(folder, (now - days * 86400, now - days * 86400))
    assert cleanup_projects(tmp_path, 30, now) == [old]
    assert not old.exists() and recent.is_dir()
    assert cleanup_projects(tmp_path / "missing", 30, now) == []


def test_worker_command_sets_java_home_and_drops_ai_key(tmp_path: Path) -> None:
    jdk = tmp_path / "jdk"
    jdk.mkdir()
    (jdk / "release").write_text('JAVA_VERSION="21.0.2"\n', encoding="utf-8")
    install = tmp_path / "ghidra"
    (install / "Ghidra").mkdir(parents=True)
    (install / "Ghidra" / "application.properties").write_text(
        "application.version=12.2\n", encoding="utf-8"
    )
    cfg = GhidraConfig(max_memory_mb=4096, install_dir=install, java_home=jdk)
    cmd = worker_command(cfg, {"OCTOV_AI_KEY": "secret", "PATH": "x"}, tmp_path)
    assert cmd.argv[1:] == [
        "-m",
        "octov.ext.ghidra.worker",
        "--ghidra",
        str(install),
        "--max-heap-mb",
        "2560",  # three eighths stay free for the JVM's non-heap memory
    ]
    assert cmd.env == {"PATH": "x", "JAVA_HOME": str(jdk)}
    with pytest.raises(GhidraError) as err:
        worker_command(GhidraConfig(install_dir=tmp_path / "nope", java_home=jdk), {}, tmp_path)
    assert err.value.kind == "not_ready"


def _ghidra_ready() -> bool:
    import importlib.util

    from octov.ext.ghidra.discover import ghidra_status

    return importlib.util.find_spec("pyghidra") is not None and ghidra_status(GhidraConfig()).ready


@pytest.mark.skipif(not _ghidra_ready(), reason="needs pyghidra, Ghidra 12.x and a JDK >= 21")
def test_real_worker_reanalyses_corrupt_project(tmp_path: Path) -> None:
    from tests.unit.test_triage_api import _suspicious

    cfg = GhidraConfig()
    data = _suspicious(tmp_path).read_bytes()
    root = tmp_path / "projects"
    st = States()
    mgr = GhidraManager(cfg, lambda: worker_command(cfg), root)
    try:
        mgr.ensure(A, data, st.on(A))
        st.wait(A, "done", 300)
        first = mgr.worker(A)
        assert first is not None and first.analysed
        assert mgr.decompile(A, 0x1000, {0x1000: "inject_main"}, {})["name"] == "inject_main"
        mgr.close(A)
        assert not first.alive()
        # a crash during save: every project file is cut short
        files = [f for f in (root / A).rglob("*") if f.is_file()]
        assert files
        for f in files:
            f.write_bytes(f.read_bytes()[: f.stat().st_size // 2])
        mgr.ensure(A, data, st.on(A))
        deadline = time.monotonic() + 300
        while st.events.count((A, "done", None)) < 2 and time.monotonic() < deadline:
            assert st.last(A) != "failed", st.events
            time.sleep(0.2)
        second = mgr.worker(A)
        assert second is not None and second.analysed  # discarded and analysed again
        assert mgr.decompile(A, 0x1000, {}, {})["entry_rva"] == 0x1000
    finally:
        mgr.shutdown_all()


def test_default_project_root_has_no_dot_folder(tmp_path: Path) -> None:
    """Ghidra refuses project paths with an element starting with '.' (so not ~/.octov)."""
    from octov.ext.ghidra.manager import default_project_root

    local = default_project_root({"LOCALAPPDATA": str(tmp_path / "Local")}, tmp_path / "home")
    assert local == tmp_path / "Local" / "OctoV" / "ghidra-projects"
    fallback = default_project_root({}, tmp_path / "home")
    assert fallback == tmp_path / "home" / "OctoV" / "ghidra-projects"
    for root in (local, fallback, default_project_root()):
        assert not any(part.startswith(".") for part in root.parts)


@pytest.mark.parametrize(("limit", "heap"), [(4096, 2560), (8192, 5120), (2048, 1280), (512, 512)])
def test_heap_leaves_room_under_the_job_limit(limit: int, heap: int) -> None:
    from octov.ext.ghidra.manager import heap_mb

    assert heap_mb(limit) == heap


def test_worker_jvm_args_keep_crash_logs_out_of_the_working_folder(tmp_path: Path) -> None:
    from octov.ext.ghidra.worker import jvm_args

    args = jvm_args(3072, tmp_path)
    assert "-Xmx3072m" in args
    assert f"-XX:ErrorFile={tmp_path / 'octov-ghidra-hs_err_pid%p.log'}" in args
