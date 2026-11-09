"""JSON-lines protocol between OctoV and the Ghidra worker process (one object per line)."""

from __future__ import annotations

import json
from typing import Any, Literal

ErrorKind = Literal["crash", "timeout", "no_function", "decompile_failed", "project_error"]


class GhidraError(Exception):
    def __init__(self, kind: ErrorKind, reason: str) -> None:
        super().__init__(reason)
        self.kind: ErrorKind = kind
        self.reason = reason


def encode(message: dict[str, Any]) -> bytes:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


def decode(line: bytes) -> dict[str, Any]:
    try:
        message = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise GhidraError("crash", "unexpected worker output") from exc
    if not isinstance(message, dict):
        raise GhidraError("crash", "unexpected worker output")
    return message
