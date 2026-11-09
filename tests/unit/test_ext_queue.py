from __future__ import annotations

import threading
import time

from octov.ext.queue import QUEUES, EngineQueue


def _wait(predicate, timeout: float = 5.0) -> bool:  # type: ignore[no-untyped-def]
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_module_queues() -> None:
    assert set(QUEUES) == {"capa", "floss"}


def test_one_job_at_a_time() -> None:
    q = EngineQueue("t1")
    order: list[str] = []
    release = threading.Event()

    def first(cancel: threading.Event) -> None:
        order.append("first-start")
        release.wait(5)
        order.append("first-end")

    def second(cancel: threading.Event) -> None:
        order.append("second")

    assert q.submit("a" * 64, first)
    assert q.submit("b" * 64, second)
    assert _wait(lambda: order == ["first-start"])
    time.sleep(0.1)
    assert order == ["first-start"] and q.queued("b" * 64)
    release.set()
    assert _wait(lambda: order == ["first-start", "first-end", "second"])


def test_duplicate_submit_is_ignored() -> None:
    q = EngineQueue("t2")
    release = threading.Event()
    ran: list[str] = []

    def job(cancel: threading.Event) -> None:
        ran.append("x")
        release.wait(5)

    assert q.submit("a" * 64, job)
    assert _wait(lambda: ran == ["x"])
    assert not q.submit("a" * 64, job)  # running
    assert q.submit("b" * 64, job)
    assert not q.submit("b" * 64, job)  # queued
    release.set()
    assert _wait(lambda: ran == ["x", "x"])


def test_close_cancels_queued_and_running() -> None:
    q = EngineQueue("t3")
    seen: list[str] = []
    started = threading.Event()

    def running(cancel: threading.Event) -> None:
        started.set()
        seen.append("cancelled" if cancel.wait(5) else "timeout")

    def never(cancel: threading.Event) -> None:
        seen.append("ran")

    q.submit("a" * 64, running)
    q.submit("b" * 64, never)
    assert started.wait(5)
    q.cancel("b" * 64)
    assert not q.queued("b" * 64)
    q.cancel("a" * 64)
    assert _wait(lambda: seen == ["cancelled"])
    time.sleep(0.1)
    assert seen == ["cancelled"]


def test_job_exception_does_not_kill_worker() -> None:
    q = EngineQueue("t4")
    ran: list[str] = []

    def boom(cancel: threading.Event) -> None:
        raise RuntimeError("bad")

    q.submit("a" * 64, boom)
    q.submit("b" * 64, lambda cancel: ran.append("ok"))
    assert _wait(lambda: ran == ["ok"])
