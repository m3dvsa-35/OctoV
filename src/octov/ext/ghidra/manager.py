"""Ghidra worker processes: one per open sample, limited, restarted and stopped when idle.

Nothing here imports pyghidra or starts Java in the OctoV process: a worker is a child
process (``octov.ext.ghidra.worker``) inside a Job Object, spoken to over JSON lines.
"""

from __future__ import annotations

import base64
import contextlib
import os
import queue
import shutil
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from octov.core.config import GhidraConfig
from octov.ext.ghidra.discover import find_ghidra, find_jdk
from octov.ext.ghidra.protocol import ERROR_KINDS, ErrorKind, GhidraError, decode, encode
from octov.ext.runner import EngineError, IsolatedProcess, spawn_isolated

StateCallback = Callable[[str, str | None, float], None]

_GRACE_S = 5.0  # on top of a request's own timeout, before the worker is declared stuck
_START_GRACE_S = 120.0  # JVM start + import, on top of the analysis timeout
_SHUTDOWN_S = 5.0
_STDERR_TAIL = 4096
_HEAP_RESERVE_MB = 512  # the job limit also covers Python and the JVM's non-heap memory


@dataclass(frozen=True)
class WorkerCommand:
    argv: list[str]
    env: dict[str, str] | None = None


def worker_command(
    cfg: GhidraConfig, env: Mapping[str, str] | None = None, home_root: Path | None = None
) -> WorkerCommand:
    """The real worker: this Python, the found Ghidra and JDK, no AI key in its environment."""
    env = os.environ if env is None else env
    install = find_ghidra(cfg, env, home_root or Path.home() / ".octov")
    if install is None:
        raise GhidraError("not_ready", "ext.reason.no_ghidra")
    jdk = find_jdk(cfg, env)
    if jdk is None:
        raise GhidraError("not_ready", "ext.reason.no_jdk")
    child_env = {k: v for k, v in env.items() if k != "OCTOV_AI_KEY"}
    child_env["JAVA_HOME"] = str(jdk[0])
    heap = max(512, cfg.max_memory_mb - _HEAP_RESERVE_MB)
    argv = [sys.executable, "-m", "octov.ext.ghidra.worker"]
    return WorkerCommand([*argv, "--ghidra", str(install), "--max-heap-mb", str(heap)], child_env)


class GhidraWorker:
    """One worker process with the sample open; one request in flight at a time."""

    def __init__(
        self, sha: str, data: bytes, cfg: GhidraConfig, command: WorkerCommand, project_root: Path
    ) -> None:
        self.sha = sha
        self.data = data
        self.cfg = cfg
        self.command = command
        self.project_dir = project_root / sha
        self.analysed = False
        self._process: IsolatedProcess | None = None
        self._replies: queue.Queue[bytes | None] = queue.Queue()
        self._stderr = bytearray()
        self._request_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._stopped = False
        self._next_id = 0

    def start(self) -> None:
        """Spawn the process and open the sample (import + analysis, or a project load)."""
        try:
            process = spawn_isolated(
                self.command.argv, self.cfg.max_memory_mb, self.command.env, stdin=True
            )
        except EngineError as exc:
            raise GhidraError("crash", exc.reason) from exc
        with self._state_lock:
            stopped = self._stopped
            if not stopped:
                self._process = process
        if stopped:  # closed while it was being started
            process.close()
            raise GhidraError("crash", "stopped")
        for target in (self._read_replies, self._read_stderr):
            threading.Thread(target=target, args=(process,), daemon=True).start()
        self.project_dir.mkdir(parents=True, exist_ok=True)
        os.utime(self.project_dir)  # last use, for cleanup_projects
        reply = self.request(
            {
                "op": "open",
                "sha256": self.sha,
                "data_b64": base64.b64encode(self.data).decode("ascii"),
                "project_dir": str(self.project_dir),
                "analysis_timeout_s": self.cfg.analysis_timeout_s,
            },
            self.cfg.analysis_timeout_s + _START_GRACE_S,
        )
        self.analysed = bool(reply.get("analysed"))

    def alive(self) -> bool:
        process = self._process
        return process is not None and process.alive()

    def request(self, op: dict[str, Any], timeout_s: float) -> dict[str, Any]:
        with self._request_lock:
            process = self._process
            if process is None or process.stdin is None or not process.alive():
                raise GhidraError("crash", self._death_reason())
            self._next_id += 1
            request_id = self._next_id
            try:
                process.stdin.write(encode({"id": request_id, **op}))
                process.stdin.flush()
            except (OSError, ValueError) as exc:
                reason = self._death_reason()
                self.stop()
                raise GhidraError("crash", reason) from exc
            deadline = time.monotonic() + timeout_s
            while True:
                try:
                    line = self._replies.get(timeout=max(0.0, deadline - time.monotonic()))
                except queue.Empty:
                    self.stop()
                    raise GhidraError("timeout", f"timed out after {timeout_s:g} s") from None
                if line is None:
                    reason = self._death_reason()  # before stop(): keeps the real exit code
                    self.stop()
                    raise GhidraError("crash", reason)
                try:
                    reply = decode(line)
                except GhidraError:
                    self.stop()
                    raise
                if reply.get("id") != request_id:
                    continue  # the answer to a request that was given up on
                if not reply.get("ok"):
                    kind = str(reply.get("error"))
                    raise GhidraError(
                        cast(ErrorKind, kind if kind in ERROR_KINDS else "decompile_failed"),
                        str(reply.get("detail") or kind),
                    )
                return reply

    def stop(self) -> None:
        """Kill the process. Safe from any thread, also while a request is in flight."""
        with self._state_lock:
            self._stopped = True
            process = self._process
        if process is not None:
            process.close()

    def shutdown(self) -> None:
        """Ask an idle worker to close its project and exit, then make sure it is gone."""
        process = self._process
        if process is not None and process.alive() and self._request_lock.acquire(blocking=False):
            try:
                if process.stdin is not None:
                    process.stdin.write(encode({"op": "shutdown"}))
                    process.stdin.flush()
                    process.wait(_SHUTDOWN_S)
            except Exception:  # already dying or too slow: stop() below kills it
                pass
            finally:
                self._request_lock.release()
        self.stop()

    def _read_replies(self, process: IsolatedProcess) -> None:
        assert process.stdout is not None
        with contextlib.suppress(OSError, ValueError):
            for line in process.stdout:
                self._replies.put(line)
        self._replies.put(None)

    def _read_stderr(self, process: IsolatedProcess) -> None:
        assert process.stderr is not None
        with contextlib.suppress(OSError, ValueError):
            for chunk in iter(lambda: process.stderr.read(4096), b""):  # type: ignore[union-attr]
                self._stderr.extend(chunk)
                del self._stderr[:-_STDERR_TAIL]

    def _death_reason(self) -> str:
        process = self._process
        if process is None:
            return "worker is not running"
        with contextlib.suppress(Exception):
            process.wait(2)
        if process.hit_memory_limit():
            return f"memory limit ({self.cfg.max_memory_mb} MB) reached"
        text = bytes(self._stderr).decode("utf-8", "replace")
        last = next((ln.strip() for ln in reversed(text.splitlines()) if ln.strip()), "")
        return f"worker exited with {process.proc.returncode}: {last}".rstrip(": ")


@dataclass
class _Entry:
    sha: str
    data: bytes
    on_state: StateCallback
    state: str = "queued"  # queued | running | done | failed
    error: str | None = None
    worker: GhidraWorker | None = None
    started: float = 0.0
    last_used: float = 0.0
    closed: bool = False
    lock: threading.RLock = field(default_factory=threading.RLock)  # one request at a time


class GhidraManager:
    """Queues samples, keeps at most ``max_workers`` workers and one open at a time."""

    def __init__(
        self,
        cfg: GhidraConfig,
        command_factory: Callable[[], WorkerCommand],
        project_root: Path,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cfg = cfg
        self.project_root = project_root
        self._command_factory = command_factory
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}
        self._pending: deque[_Entry] = deque()
        self._opening: _Entry | None = None

    # -- lifecycle ------------------------------------------------------------------------

    def ensure(self, sha: str, data: bytes, on_state: StateCallback) -> None:
        """Queue the sample for its worker; a no-op unless it is new or had failed."""
        with self._lock:
            known = self._entries.get(sha)
            if known is not None and known.state != "failed":
                return
            entry = _Entry(sha, data, on_state)
            self._entries[sha] = entry
            self._pending.append(entry)
        on_state("queued", None, 0.0)
        self._pump()

    def close(self, sha: str) -> None:
        with self._lock:
            entry = self._entries.pop(sha, None)
            if entry is None:
                return
            entry.closed = True
            if entry in self._pending:
                self._pending.remove(entry)
            worker, entry.worker = entry.worker, None
            busy = entry is self._opening or not entry.lock.acquire(blocking=False)
        if worker is not None:
            if busy:
                worker.stop()  # analysing or mid-request: no time for a clean exit
            else:
                worker.shutdown()
        if not busy:
            entry.lock.release()
        self._pump()

    def shutdown_all(self) -> None:
        with self._lock:
            shas = list(self._entries)
        for sha in shas:
            self.close(sha)

    def reap_idle(self) -> None:
        """Stop workers nobody used for ``idle_minutes``; ``decompile`` restarts them."""
        limit = self.cfg.idle_minutes * 60
        with self._lock:
            idle = [
                e
                for e in self._entries.values()
                if e.state == "done"
                and e.worker is not None
                and self._clock() - e.last_used >= limit
            ]
        for entry in idle:
            if not entry.lock.acquire(blocking=False):
                continue  # in use right now
            try:
                with self._lock:
                    worker, entry.worker = entry.worker, None
                if worker is not None:
                    worker.shutdown()
            finally:
                entry.lock.release()
        self._pump()

    def worker(self, sha: str) -> GhidraWorker | None:
        with self._lock:
            entry = self._entries.get(sha)
            return entry.worker if entry is not None else None

    # -- requests -------------------------------------------------------------------------

    def decompile(
        self, sha: str, rva: int, names: Mapping[int, str], comments: Mapping[int, str]
    ) -> dict[str, Any]:
        op = {
            "op": "decompile",
            "rva": rva,
            "names": {str(k): v for k, v in names.items()},
            "comments": {str(k): v for k, v in comments.items()},
            "timeout_s": self.cfg.decompile_timeout_s,
        }
        return self._request(sha, op, self.cfg.decompile_timeout_s + _GRACE_S)

    def functions(self, sha: str) -> list[tuple[int, str]]:
        reply = self._request(sha, {"op": "functions"}, self.cfg.decompile_timeout_s + _GRACE_S)
        return [(int(rva), str(name)) for rva, name in reply["functions"]]

    # -- internals ------------------------------------------------------------------------

    def _pump(self) -> None:
        with self._lock:
            if self._opening is not None or not self._pending:
                return
            alive = sum(1 for e in self._entries.values() if e.worker is not None)
            if alive >= self.cfg.max_workers:
                return
            entry = self._pending.popleft()
            self._opening = entry
            entry.state = "running"
            entry.started = self._clock()
        threading.Thread(target=self._open, args=(entry,), daemon=True).start()

    def _new_worker(self, entry: _Entry) -> GhidraWorker:
        """A worker registered on the entry, so ``close`` can always reach and kill it."""
        worker = GhidraWorker(
            entry.sha, entry.data, self.cfg, self._command_factory(), self.project_root
        )
        with self._lock:
            if entry.closed:
                raise GhidraError("not_ready", "closed")
            entry.worker = worker
        return worker

    def _drop_worker(self, entry: _Entry) -> None:
        with self._lock:
            worker, entry.worker = entry.worker, None
        if worker is not None:
            worker.stop()

    def _open(self, entry: _Entry) -> None:
        entry.on_state("running", None, 0.0)
        failure: GhidraError | None = None
        with entry.lock:
            for _attempt in range(2):  # a crashed worker is restarted once
                try:
                    self._new_worker(entry).start()
                    failure = None
                    break
                except GhidraError as exc:
                    failure = exc
                    self._drop_worker(entry)
                    if exc.kind == "project_error":
                        shutil.rmtree(self.project_root / entry.sha, ignore_errors=True)
                    elif exc.kind != "crash":
                        break
        elapsed = self._clock() - entry.started
        with self._lock:
            self._opening = None
            closed = entry.closed
            if not closed:
                entry.state = "done" if failure is None else "failed"
                entry.error = failure.reason if failure is not None else None
                entry.last_used = self._clock()
        if closed:
            self._drop_worker(entry)
        else:
            entry.on_state(entry.state, entry.error, elapsed)
        self._pump()

    def _request(self, sha: str, op: dict[str, Any], timeout_s: float) -> dict[str, Any]:
        with self._lock:
            entry = self._entries.get(sha)
        if entry is None:
            raise GhidraError("not_ready", "unknown")
        with entry.lock:
            if entry.closed or entry.state != "done":
                raise GhidraError("not_ready", "closed" if entry.closed else entry.state)
            failure: GhidraError | None = None
            for _attempt in range(2):  # a crashed worker is restarted once
                try:
                    worker = entry.worker
                    if worker is None or not worker.alive():  # idle-stopped or just killed
                        worker = self._new_worker(entry)
                        worker.start()
                    reply = worker.request(op, timeout_s)
                    entry.last_used = self._clock()
                    return reply
                except GhidraError as exc:
                    if exc.kind not in ("crash", "timeout"):
                        raise
                    self._drop_worker(entry)
                    if exc.kind == "timeout":
                        raise  # no retry: the same function would hang again
                    failure = exc
            assert failure is not None
            with self._lock:
                entry.state = "failed"
                entry.error = failure.reason
        entry.on_state("failed", failure.reason, 0.0)
        self._pump()
        raise GhidraError("crash", failure.reason)


def cleanup_projects(root: Path, keep_days: int, now: float) -> list[Path]:
    """Delete project folders last used (folder mtime) more than ``keep_days`` ago."""
    if not root.is_dir():
        return []
    removed: list[Path] = []
    for folder in sorted(root.iterdir()):
        if folder.is_dir() and now - folder.stat().st_mtime > keep_days * 86400:
            shutil.rmtree(folder, ignore_errors=True)
            removed.append(folder)
    return removed
