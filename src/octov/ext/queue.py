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
        self._pending: deque[tuple[str, object, Job]] = deque()
        self._running: tuple[str, object, threading.Event] | None = None
        threading.Thread(target=self._work, daemon=True, name=f"octov-{engine}").start()

    def submit(self, sha: str, job: Job, owner: object = None) -> bool:
        """Queue ``job``; False when the same sample (``sha`` + ``owner``) is queued or running.

        ``owner`` is the opened-sample object: a sample closed and opened again is a new
        owner, so its job queues behind the old one instead of being dropped.
        """
        with self._cond:
            running = self._running
            if running is not None and running[0] == sha and running[1] is owner:
                return False
            if any(s == sha and o is owner for s, o, _ in self._pending):
                return False
            self._pending.append((sha, owner, job))
            self._cond.notify()
            return True

    def cancel(self, sha: str) -> None:
        """Drop the queued job of ``sha`` and signal its running job to stop."""
        with self._cond:
            self._pending = deque(e for e in self._pending if e[0] != sha)
            if self._running is not None and self._running[0] == sha:
                self._running[2].set()

    def queued(self, sha: str) -> bool:
        with self._cond:
            return any(e[0] == sha for e in self._pending)

    def _work(self) -> None:
        while True:
            with self._cond:
                while not self._pending:
                    self._cond.wait()
                sha, owner, job = self._pending.popleft()
                cancel = threading.Event()
                self._running = (sha, owner, cancel)
            try:
                job(cancel)
            except Exception:  # a job's failure must never stop the queue
                log.exception("%s job for %s failed", self.engine, sha[:12])
            finally:
                with self._cond:
                    self._running = None


QUEUES: dict[str, EngineQueue] = {e: EngineQueue(e) for e in ("capa", "floss", "library")}
