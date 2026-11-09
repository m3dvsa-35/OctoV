"""Run an analysis engine as an isolated child process.

The child starts suspended, is placed in a Windows Job Object (memory limit, the
whole process tree dies with the job) and is resumed. It runs at below-normal
priority; stdout is collected fully, stderr only its tail (for error reasons).
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

ErrorKind = Literal["timeout", "memory", "crash", "cancelled", "bad_output"]
_STDERR_TAIL = 4096
_POLL_S = 0.1


@dataclass(frozen=True)
class EngineRun:
    stdout: bytes
    stderr_tail: str
    elapsed_s: float


class EngineError(Exception):
    def __init__(self, kind: ErrorKind, reason: str) -> None:
        super().__init__(reason)
        self.kind: ErrorKind = kind
        self.reason = reason


class _Job:
    """Windows Job Object with a memory limit; a no-op elsewhere."""

    def __init__(self, max_memory_mb: int) -> None:
        self.handle: int | None = None
        self.limit = max_memory_mb * 1024 * 1024
        if sys.platform != "win32":
            return
        import ctypes
        from ctypes import wintypes

        class _IoCounters(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]

        class _Basic(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _Extended(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _Basic),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self._ctypes = ctypes
        self._Extended = _Extended
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        self._k32 = k32
        handle = k32.CreateJobObjectW(None, None)
        if not handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
        self.handle = int(handle)
        info = _Extended()
        info.BasicLimitInformation.LimitFlags = 0x2000 | 0x200  # KILL_ON_JOB_CLOSE | JOB_MEMORY
        info.JobMemoryLimit = self.limit
        ok = k32.SetInformationJobObject(
            wintypes.HANDLE(self.handle), 9, ctypes.byref(info), ctypes.sizeof(info)
        )
        if not ok:
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")

    def adopt_and_resume(self, proc: subprocess.Popen[bytes]) -> None:
        if self.handle is None:
            return
        from ctypes import wintypes

        handle = wintypes.HANDLE(int(proc._handle))  # type: ignore[attr-defined]
        if not self._k32.AssignProcessToJobObject(wintypes.HANDLE(self.handle), handle):
            raise OSError(self._ctypes.get_last_error(), "AssignProcessToJobObject failed")
        status = self._ctypes.WinDLL("ntdll").NtResumeProcess(handle)
        if status != 0:
            raise OSError(status, "NtResumeProcess failed")

    def peak_memory(self) -> int:
        if self.handle is None:
            return 0
        from ctypes import wintypes

        info = self._Extended()
        self._k32.QueryInformationJobObject(
            wintypes.HANDLE(self.handle),
            9,
            self._ctypes.byref(info),
            self._ctypes.sizeof(info),
            None,
        )
        return int(info.PeakJobMemoryUsed)

    def kill(self) -> None:
        if self.handle is not None:
            from ctypes import wintypes

            self._k32.TerminateJobObject(wintypes.HANDLE(self.handle), 1)

    def close(self) -> None:
        if self.handle is not None:
            from ctypes import wintypes

            self._k32.CloseHandle(wintypes.HANDLE(self.handle))
            self.handle = None


def _creation_flags() -> int:
    if sys.platform != "win32":
        return 0
    # CREATE_SUSPENDED | BELOW_NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW
    return 0x00000004 | 0x00004000 | 0x08000000


class IsolatedProcess:
    """A child process inside its own Job Object (memory limit, tree dies with the job)."""

    def __init__(self, proc: subprocess.Popen[bytes], job: _Job, max_memory_mb: int) -> None:
        self.proc = proc
        self.job = job
        self.max_memory_mb = max_memory_mb
        self.stdin = proc.stdin
        self.stdout = proc.stdout
        self.stderr = proc.stderr

    @property
    def pid(self) -> int:
        return self.proc.pid

    def alive(self) -> bool:
        return self.proc.poll() is None

    def wait(self, timeout: float | None = None) -> int:
        return self.proc.wait(timeout)

    def peak_memory(self) -> int:
        return self.job.peak_memory()

    def hit_memory_limit(self) -> bool:
        return self.job.peak_memory() >= self.job.limit - (16 << 20)

    def kill(self) -> None:
        self.job.kill()
        with contextlib.suppress(OSError):
            self.proc.kill()
        self.proc.wait()

    def close(self) -> None:
        """Kill whatever is left and release the job and the pipes."""
        self.kill()
        self.job.close()
        for pipe in (self.stdin, self.stdout, self.stderr):
            if pipe is not None:
                with contextlib.suppress(OSError):
                    pipe.close()


def spawn_isolated(
    argv: list[str],
    max_memory_mb: int,
    env: Mapping[str, str] | None = None,
    *,
    stdin: bool = False,
) -> IsolatedProcess:
    """Start ``argv`` suspended, put it in a Job Object and resume it (below-normal priority)."""
    try:
        job = _Job(max_memory_mb)
    except OSError as exc:
        raise EngineError("crash", f"cannot isolate engine: {exc}") from exc
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env) if env is not None else None,
            creationflags=_creation_flags(),
        )
    except OSError as exc:
        job.close()
        raise EngineError("crash", f"cannot start engine: {exc}") from exc
    try:
        job.adopt_and_resume(proc)
    except OSError as exc:
        proc.kill()
        proc.communicate(timeout=10)  # reap it and close its pipes
        job.close()
        raise EngineError("crash", f"cannot isolate engine: {exc}") from exc
    return IsolatedProcess(proc, job, max_memory_mb)


def run_engine(
    argv: list[str], *, timeout_s: float, max_memory_mb: int, cancel: threading.Event
) -> EngineRun:
    start = time.monotonic()
    isolated = spawn_isolated(argv, max_memory_mb)
    proc, job = isolated.proc, isolated.job
    out: list[bytes] = []
    err = bytearray()

    def read_out() -> None:
        assert proc.stdout is not None
        out.append(proc.stdout.read())

    def read_err() -> None:
        assert proc.stderr is not None
        for chunk in iter(lambda: proc.stderr.read(4096), b""):  # type: ignore[union-attr]
            err.extend(chunk)
            del err[:-_STDERR_TAIL]

    try:
        readers = [threading.Thread(target=f, daemon=True) for f in (read_out, read_err)]
        for r in readers:
            r.start()
        failure: EngineError | None = None
        while proc.poll() is None:
            if cancel.is_set():
                failure = EngineError("cancelled", "cancelled")
            elif time.monotonic() - start > timeout_s:
                failure = EngineError("timeout", f"timed out after {timeout_s:g} s")
            if failure is not None:
                job.kill()
                proc.kill()
                proc.wait()
                break
            time.sleep(_POLL_S)
        for r in readers:
            r.join(timeout=5)
        elapsed = time.monotonic() - start
        stderr_tail = err.decode("utf-8", "replace")
        if failure is not None:
            raise failure
        if proc.returncode != 0:
            if "MemoryError" in stderr_tail or job.peak_memory() >= job.limit - (16 << 20):
                raise EngineError("memory", f"memory limit ({max_memory_mb} MB) reached")
            last = next((ln for ln in reversed(stderr_tail.splitlines()) if ln.strip()), "")
            raise EngineError("crash", f"engine exited with {proc.returncode}: {last}".strip())
        return EngineRun(out[0] if out else b"", stderr_tail, elapsed)
    finally:
        job.kill()
        job.close()


def parse_json(run: EngineRun) -> dict[str, Any]:
    try:
        doc = json.loads(run.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EngineError("bad_output", "unexpected engine output") from exc
    if not isinstance(doc, dict):
        raise EngineError("bad_output", "unexpected engine output")
    return doc
