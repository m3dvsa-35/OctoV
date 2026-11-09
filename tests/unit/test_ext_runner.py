from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from octov.ext.runner import EngineError, EngineRun, parse_json, run_engine

FAKE = str(Path(__file__).resolve().parents[1] / "fixtures" / "fake_engine.py")


def _run(mode: str, *, timeout_s: float = 30, max_memory_mb: int = 1024, cancel=None):  # type: ignore[no-untyped-def]
    return run_engine(
        [sys.executable, FAKE, mode],
        timeout_s=timeout_s,
        max_memory_mb=max_memory_mb,
        cancel=cancel or threading.Event(),
    )


def test_json_output_is_returned() -> None:
    run = _run("ok")
    assert parse_json(run) == {"ok": True}
    assert run.elapsed_s >= 0


def test_nonzero_exit_is_crash() -> None:
    with pytest.raises(EngineError) as err:
        _run("exit3")
    assert err.value.kind == "crash"
    assert "bad PE header" in err.value.reason


def test_timeout_kills_process() -> None:
    start = time.monotonic()
    with pytest.raises(EngineError) as err:
        _run("sleep", timeout_s=1)
    assert err.value.kind == "timeout"
    assert "timed out after 1 s" in err.value.reason
    assert time.monotonic() - start < 10


def test_cancel_kills_process() -> None:
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    start = time.monotonic()
    with pytest.raises(EngineError) as err:
        _run("sleep", cancel=cancel)
    assert err.value.kind == "cancelled"
    assert time.monotonic() - start < 10


@pytest.mark.skipif(sys.platform != "win32", reason="Job Object memory limit is Windows-only")
def test_memory_limit() -> None:
    with pytest.raises(EngineError) as err:
        _run("alloc", max_memory_mb=100)
    assert err.value.kind == "memory"


def test_bad_json_is_failed() -> None:
    with pytest.raises(EngineError) as err:
        parse_json(_run("garbage"))
    assert err.value.kind == "bad_output"
    assert err.value.reason == "unexpected engine output"


@pytest.mark.parametrize("stdout", [b"", b"[1, 2]", b"\xff\xfe"])
def test_empty_or_non_object_output_is_bad(stdout: bytes) -> None:
    with pytest.raises(EngineError) as err:
        parse_json(EngineRun(stdout=stdout, stderr_tail="", elapsed_s=0.1))
    assert err.value.kind == "bad_output"
