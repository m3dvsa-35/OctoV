"""Stand-in for the Ghidra worker: speaks the JSON-lines protocol with canned answers.

Modes (argv[1]): ok, slow (open takes 1.5 s), crash_on_decompile, hang (decompile never
answers), project_error (a reopened project is reported broken and re-analysed).
A file argv[2] (optional) gets one line per request op, so tests can count calls.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

LINES = [
    ["void FUN_00401000(void)", []],
    ["{", []],
    ["  WriteProcessMemory(hProcess,param_2);", [0x1007]],
    ["  CreateRemoteThread(hProcess,0,0,param_4,0,0,0);", [0x100D]],
    ["  return;", [0x1013]],
    ["}", []],
]


def reply(message: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "ok"
    log = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    for raw in sys.stdin:
        msg = json.loads(raw)
        op, mid = msg.get("op"), msg.get("id")
        if log is not None:
            with log.open("a", encoding="utf-8") as fh:
                fh.write(f"{op}\n")
        if op == "shutdown":
            return 0
        if op == "open":
            if mode == "slow":
                time.sleep(1.5)
            project = Path(msg["project_dir"])
            marker = project / ".fake-analysed"
            analysed = not marker.exists() or mode == "project_error"
            project.mkdir(parents=True, exist_ok=True)
            marker.write_text("x", encoding="utf-8")
            reply({"id": mid, "ok": True, "analysed": analysed, "seconds": 0.0})
        elif op == "functions":
            reply({"id": mid, "ok": True, "functions": [[0x1000, "FUN_00401000"]]})
        elif op == "decompile":
            if mode == "crash_on_decompile":
                return 3
            if mode == "hang":
                time.sleep(3600)
            rva = int(msg["rva"])
            if not 0x1000 <= rva < 0x1020:
                reply({"id": mid, "ok": False, "error": "no_function", "detail": hex(rva)})
                continue
            name = msg.get("names", {}).get("4096", "FUN_00401000")
            lines = [[text.replace("FUN_00401000", name), rvas] for text, rvas in LINES]
            reply(
                {
                    "id": mid,
                    "ok": True,
                    "entry_rva": 0x1000,
                    "name": name,
                    "lines": lines,
                    "warnings": [],
                }
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
