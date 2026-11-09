"""One worker per engine for the whole app: at most one capa and one FLOSS process at a time."""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Callable

Job = Callable[[threading.Event], None]
log = logging.getLogger(__name__)


class EngineQueue:
    def __init__(self, engine: str) -> None:
        self.engine = engine
        self._cond = threading.Condition()
        self._pending: deque[tuple[str, Job]] = deque()
        self._running: tuple[str, threading.Event] | None = None
        threading.Thread(target=self._work, daemon=True, name=f"octov-{engine}").start()

    def submit(self, sha: str, job: Job) -> bool:
        """Queue ``job`` for ``sha``; False when that sample is already queued or running."""
        with self._cond:
            if self._running is not None and self._running[0] == sha:
                return False
            if any(s == sha for s, _ in self._pending):
                return False
            self._pending.append((sha, job))
            self._cond.notify()
            return True

    def cancel(self, sha: str) -> None:
        """Drop the queued job of ``sha`` and signal its running job to stop."""
        with self._cond:
            self._pending = deque((s, j) for s, j in self._pending if s != sha)
            if self._running is not None and self._running[0] == sha:
                self._running[1].set()

    def queued(self, sha: str) -> bool:
        with self._cond:
            return any(s == sha for s, _ in self._pending)

    def _work(self) -> None:
        while True:
            with self._cond:
                while not self._pending:
                    self._cond.wait()
                sha, job = self._pending.popleft()
                cancel = threading.Event()
                self._running = (sha, cancel)
            try:
                job(cancel)
            except Exception:  # a job's failure must never stop the queue
                log.exception("%s job for %s failed", self.engine, sha[:12])
            finally:
                with self._cond:
                    self._running = None


QUEUES: dict[str, EngineQueue] = {"capa": EngineQueue("capa"), "floss": EngineQueue("floss")}
