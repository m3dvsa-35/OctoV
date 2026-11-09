"""Ghidra worker: runs ONLY in its own child process (``python -m octov.ext.ghidra.worker``).

Reads JSON-lines requests on stdin, answers on the original stdout (the JVM's own output is
redirected to stderr so it can never corrupt the protocol). See ``protocol.py`` and the
Phase 3 design §5.3. The sample arrives as bytes and is imported from memory.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from octov.ext.ghidra.protocol import decode, encode

PROGRAM = "sample"


class Worker:
    def __init__(self, out: Any) -> None:
        self.out = out
        self.project: Any = None
        self.program: Any = None
        self.consumer: Any = None  # a java.lang.Object owning the open program

    def reply(self, message: dict[str, Any]) -> None:
        self.out.write(encode(message))
        self.out.flush()

    # -- requests ---------------------------------------------------------------------

    def open(self, msg: dict[str, Any]) -> dict[str, Any]:
        project_dir = Path(msg["project_dir"])
        start = time.monotonic()
        analysed = False
        if (project_dir / f"{PROGRAM}.gpr").is_file():
            try:
                self._load(project_dir)
            except Exception:  # broken project (crash during save): start over
                self._close()
                shutil.rmtree(project_dir, ignore_errors=True)
        if self.program is None:
            self._import(project_dir, base64.b64decode(msg["data_b64"]))
            self._analyse(int(msg.get("analysis_timeout_s", 900)))
            analysed = True
        return {"ok": True, "analysed": analysed, "seconds": round(time.monotonic() - start, 1)}

    def functions(self, msg: dict[str, Any]) -> dict[str, Any]:
        base = self.program.getImageBase()
        fm = self.program.getFunctionManager()
        return {
            "ok": True,
            "functions": [
                [int(f.getEntryPoint().subtract(base)), str(f.getName())]
                for f in fm.getFunctions(True)
            ],
        }

    def decompile(self, msg: dict[str, Any]) -> dict[str, Any]:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.app.decompiler.component import DecompilerUtils
        from ghidra.program.model.listing import CommentType
        from ghidra.program.model.symbol import SourceType
        from ghidra.util.task import TaskMonitor

        program = self.program
        base = program.getImageBase()
        fm = program.getFunctionManager()
        rva = int(msg["rva"])
        tx = program.startTransaction("octov annotations")
        try:
            for key, name in msg.get("names", {}).items():
                fn = fm.getFunctionAt(base.add(int(key)))
                if fn is not None:
                    # an invalid or duplicate name keeps Ghidra's own
                    with contextlib.suppress(Exception):
                        fn.setName(str(name), SourceType.USER_DEFINED)
            listing = program.getListing()
            for key, text in msg.get("comments", {}).items():
                listing.setComment(base.add(int(key)), CommentType.PRE, str(text))
            fn = fm.getFunctionContaining(base.add(rva))
            if fn is None:
                return {"ok": False, "error": "no_function", "detail": hex(rva)}
            iface = DecompInterface()
            iface.openProgram(program)
            try:
                result = iface.decompileFunction(
                    fn, int(msg.get("timeout_s", 30)), TaskMonitor.DUMMY
                )
                if not result.decompileCompleted():
                    detail = str(result.getErrorMessage() or "decompiler gave no result")
                    return {"ok": False, "error": "decompile_failed", "detail": detail}
                lines = []
                for line in DecompilerUtils.toLines(result.getCCodeMarkup()):
                    tokens = list(line.getAllTokens())
                    text = " " * int(line.getIndent()) + "".join(str(t) for t in tokens)
                    rvas = sorted(
                        {
                            int(t.getMinAddress().subtract(base))
                            for t in tokens
                            if t.getMinAddress() is not None
                        }
                    )
                    lines.append([text, [r for r in rvas if r >= 0]])
                warnings = [str(result.getErrorMessage())] if result.getErrorMessage() else []
                return {
                    "ok": True,
                    "entry_rva": int(fn.getEntryPoint().subtract(base)),
                    "name": str(fn.getName()),
                    "lines": lines,
                    "warnings": warnings,
                }
            finally:
                iface.dispose()
        finally:
            program.endTransaction(tx, False)  # never save analyst names into the project

    # -- project ----------------------------------------------------------------------

    def _import(self, project_dir: Path, data: bytes) -> None:
        import jpype
        import pyghidra
        from ghidra.app.util.bin import ByteArrayProvider
        from ghidra.util.task import TaskMonitor

        project_dir.mkdir(parents=True, exist_ok=True)
        self.project = pyghidra.open_project(str(project_dir), PROGRAM, create=True)
        provider = ByteArrayProvider(jpype.JArray(jpype.JByte)(data))
        loader = pyghidra.program_loader().project(self.project).source(provider).name(PROGRAM)
        with loader.load() as results:
            results.save(TaskMonitor.DUMMY)
            self.program = results.getPrimaryDomainObject(self._consumer())

    def _load(self, project_dir: Path) -> None:
        import pyghidra
        from ghidra.util.task import TaskMonitor

        self.project = pyghidra.open_project(str(project_dir), PROGRAM, create=False)
        domain_file = self.project.getProjectData().getFile("/" + PROGRAM)
        if domain_file is None:
            raise RuntimeError("program missing from project")
        self.program = domain_file.getDomainObject(self._consumer(), True, False, TaskMonitor.DUMMY)

    def _analyse(self, timeout_s: int) -> None:
        import pyghidra
        from ghidra.util.task import TaskMonitor, TimeoutTaskMonitor
        from java.util.concurrent import TimeUnit

        monitor = TimeoutTaskMonitor.timeoutIn(timeout_s, TimeUnit.SECONDS, TaskMonitor.DUMMY)
        pyghidra.analyze(self.program, monitor)
        self.program.save("octov auto-analysis", TaskMonitor.DUMMY)

    def _consumer(self) -> Any:
        from java.lang import Object

        if self.consumer is None:
            self.consumer = Object()
        return self.consumer

    def _close(self) -> None:
        try:
            if self.program is not None:
                self.program.release(self.consumer)
            if self.project is not None:
                self.project.close()
        except Exception:
            pass
        self.program = self.project = None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="octov-ghidra-worker")
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--max-heap-mb", type=int, default=3584)
    args = parser.parse_args(argv)

    # keep the real stdout for the protocol; everything else (JVM, Ghidra logs) -> stderr
    out = os.fdopen(os.dup(1), "wb")
    os.dup2(2, 1)
    sys.stdout = sys.stderr

    import pyghidra

    launcher = pyghidra.HeadlessPyGhidraLauncher(install_dir=args.ghidra)
    launcher.add_vmargs(f"-Xmx{args.max_heap_mb}m")
    launcher.start()

    worker = Worker(out)
    handlers = {"open": worker.open, "functions": worker.functions, "decompile": worker.decompile}
    for raw in sys.stdin.buffer:
        msg = decode(raw)
        op = msg.get("op")
        if op == "shutdown":
            break
        handler = handlers.get(str(op))
        try:
            answer = (
                handler(msg)
                if handler
                else {"ok": False, "error": "crash", "detail": f"unknown op {op}"}
            )
        except Exception as exc:  # one bad request must not kill the worker
            answer = {
                "ok": False,
                "error": "decompile_failed",
                "detail": f"{type(exc).__name__}: {exc}",
            }
        worker.reply({"id": msg.get("id"), **answer})
    worker._close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
