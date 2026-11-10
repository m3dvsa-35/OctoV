from __future__ import annotations

import base64
import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from octov.ext.ghidra.protocol import GhidraError, decode, encode

FAKE = str(Path(__file__).resolve().parents[1] / "fixtures" / "fake_ghidra_worker.py")


def test_protocol_round_trip() -> None:
    msg = {"id": 3, "op": "decompile", "rva": 4096, "names": {"4096": "ünï"}}
    line = encode(msg)
    assert line.endswith(b"\n") and b"\n" not in line[:-1]
    assert decode(line) == msg


def test_decode_rejects_non_object() -> None:
    with pytest.raises(GhidraError) as err:
        decode(b"[1, 2]\n")
    assert err.value.kind == "crash"


def _talk(proc: subprocess.Popen[bytes], msg: dict[str, Any]) -> dict[str, Any]:
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(encode(msg))
    proc.stdin.flush()
    return decode(proc.stdout.readline())


def test_fake_worker_contract(tmp_path: Path) -> None:
    proc = subprocess.Popen(
        [sys.executable, FAKE, "ok"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    data = base64.b64encode(b"MZ" + b"\0" * 64).decode()
    opened = _talk(
        proc,
        {
            "id": 1,
            "op": "open",
            "sha256": "a" * 64,
            "data_b64": data,
            "project_dir": str(tmp_path),
            "analysis_timeout_s": 60,
        },
    )
    assert opened == {"id": 1, "ok": True, "analysed": True, "seconds": 0.0}
    reply = _talk(
        proc,
        {"id": 2, "op": "decompile", "rva": 0x1000, "names": {}, "comments": {}, "timeout_s": 30},
    )
    assert reply["ok"] and reply["entry_rva"] == 0x1000
    assert [0x1007] in [rvas for _, rvas in reply["lines"]]
    missing = _talk(
        proc,
        {"id": 3, "op": "decompile", "rva": 0x9999, "names": {}, "comments": {}, "timeout_s": 30},
    )
    assert missing == {"id": 3, "ok": False, "error": "no_function", "detail": "0x9999"}
    proc.stdin.write(encode({"id": 4, "op": "shutdown"}))  # type: ignore[union-attr]
    proc.stdin.flush()  # type: ignore[union-attr]
    assert proc.wait(10) == 0


def _ghidra_ready() -> bool:
    if importlib.util.find_spec("pyghidra") is None:
        return False
    from octov.core.config import GhidraConfig
    from octov.ext.ghidra.discover import ghidra_status

    return ghidra_status(GhidraConfig()).ready


@pytest.mark.skipif(not _ghidra_ready(), reason="needs pyghidra, Ghidra 12.x and a JDK >= 21")
def test_real_ghidra_decompiles_and_rolls_back_names(tmp_path: Path) -> None:
    import os

    from octov.core.config import GhidraConfig
    from octov.ext.ghidra.discover import find_ghidra, find_jdk
    from tests.unit.test_triage_api import _suspicious

    cfg = GhidraConfig()
    jdk = find_jdk(cfg, os.environ)
    install = find_ghidra(cfg, os.environ, Path.home() / ".octov")
    assert jdk is not None and install is not None
    env = {**os.environ, "JAVA_HOME": str(jdk[0])}
    cmd = [
        sys.executable,
        "-m",
        "octov.ext.ghidra.worker",
        "--ghidra",
        str(install),
        "--max-heap-mb",
        "2048",
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
    try:
        data = base64.b64encode(_suspicious(tmp_path).read_bytes()).decode()
        opened = _talk(
            proc,
            {
                "id": 1,
                "op": "open",
                "sha256": "b" * 64,
                "data_b64": data,
                "project_dir": str(tmp_path / "proj"),
                "analysis_timeout_s": 600,
            },
        )
        assert opened["ok"] and opened["analysed"] is True
        named = _talk(
            proc,
            {
                "id": 2,
                "op": "decompile",
                "rva": 0x1004,
                "names": {"4096": "inject_main"},
                "comments": {},
                "timeout_s": 60,
            },
        )
        assert named["ok"] and named["entry_rva"] == 0x1000 and named["name"] == "inject_main"
        text = "\n".join(t for t, _ in named["lines"])
        assert "CreateRemoteThread" in text and "inject_main" in text
        assert any(0x100D in rvas for _, rvas in named["lines"])
        plain = _talk(
            proc,
            {
                "id": 3,
                "op": "decompile",
                "rva": 0x1000,
                "names": {},
                "comments": {},
                "timeout_s": 60,
            },
        )
        assert plain["name"] != "inject_main"  # names were rolled back, not saved
        funcs = _talk(proc, {"id": 4, "op": "functions"})
        assert [0x1000, plain["name"]] in funcs["functions"]

    finally:
        proc.kill()
        proc.wait(30)
    # reopen: the saved project is loaded, not re-analysed
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
    try:
        again = _talk(
            proc,
            {
                "id": 1,
                "op": "open",
                "sha256": "b" * 64,
                "data_b64": data,
                "project_dir": str(tmp_path / "proj"),
                "analysis_timeout_s": 600,
            },
        )
        assert again["ok"] and again["analysed"] is False
    finally:
        proc.kill()
        proc.wait(30)
