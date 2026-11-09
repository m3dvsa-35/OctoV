from __future__ import annotations

from pathlib import Path

import pytest

from octov.core.analysis.facts import Evidence, Fact
from octov.ext import cache
from octov.ext.ghidra.model import (
    DecompiledFunction,
    Line,
    annotation_hash,
    cache_path,
    line_marks,
    suspicious_apis,
)
from octov.ext.ghidra.protocol import GhidraError

REPLY = {
    "id": 2,
    "ok": True,
    "entry_rva": 0x1000,
    "name": "FUN_00401000",
    "lines": [
        ["void FUN_00401000(void)", []],
        ["{", []],
        ["  WriteProcessMemory(hProcess,param_2);", [0x1007]],
        ["  hThread = CreateRemoteThread (hProcess,0,0,param_4,0,0,0);", [0x100D, 0x1010]],
        ["  GetTickCount();", [0x1013]],
        ["  my_send_helper(sendbuf);", [0x1018]],
        ["  sendW = 3; // CreateRemoteThread is not called here", [0x101C]],
        ["}", []],
    ],
    "warnings": ["Removing unreachable block"],
}


def test_from_reply_maps_lines() -> None:
    fn = DecompiledFunction.from_reply(REPLY)
    assert fn.entry_rva == 0x1000 and fn.name == "FUN_00401000"
    assert fn.lines[3] == Line(
        "  hThread = CreateRemoteThread (hProcess,0,0,param_4,0,0,0);", (0x100D, 0x1010)
    )
    assert fn.warnings == ("Removing unreachable block",)
    assert fn.to_dict() == {
        "entry_rva": 0x1000,
        "name": "FUN_00401000",
        "lines": [{"text": text, "rvas": rvas} for text, rvas in REPLY["lines"]],  # type: ignore[union-attr, misc]
        "warnings": ["Removing unreachable block"],
    }
    assert DecompiledFunction.from_dict(fn.to_dict()) == fn


@pytest.mark.parametrize(
    "doc",
    [{}, {"entry_rva": "x", "name": "f", "lines": []}, {"entry_rva": 1, "name": "f", "lines": [3]}],
)
def test_from_dict_rejects_damaged_cache(doc: dict[str, object]) -> None:
    assert DecompiledFunction.from_dict(doc) is None


def test_decompile_outside_function() -> None:
    with pytest.raises(GhidraError) as err:
        DecompiledFunction.from_reply({"ok": False, "error": "no_function", "detail": "0x9999"})
    assert err.value.kind == "no_function" and err.value.reason == "0x9999"


def test_annotation_hash_stable_and_order_free() -> None:
    one = annotation_hash({0x1000: "a", 0x2000: "b"}, {0x1004: "note"})
    two = annotation_hash({0x2000: "b", 0x1000: "a"}, {0x1004: "note"})
    assert one == two and len(one) == 16 and int(one, 16) >= 0
    assert annotation_hash({0x1000: "a2", 0x2000: "b"}, {0x1004: "note"}) != one
    assert annotation_hash({0x1000: "a", 0x2000: "b"}, {}) != one
    # a name is not a comment
    assert annotation_hash({0x1000: "a"}, {}) != annotation_hash({}, {0x1000: "a"})


def _fact(rva: int | None, severity: str = "high") -> Fact:
    return Fact(
        kind="rule",
        source_id="EVA-001",
        severity=severity,  # type: ignore[arg-type]
        title="Remote thread injection",
        evidence=(Evidence("call", rva=rva), Evidence("string", offset=0x400)),
    )


def test_fact_mark_on_evidence_line() -> None:
    fn = DecompiledFunction.from_reply(REPLY)
    fact = _fact(0x1010)
    marks = line_marks(fn, [fact, _fact(None, "low"), _fact(0x5000)], {})
    assert marks[3] == [{"kind": "fact", "fact_id": fact.id, "severity": "high"}]
    assert [m for i, m in enumerate(marks) if i != 3] == [[]] * 7


def test_api_mark_on_suspicious_call() -> None:
    fn = DecompiledFunction.from_reply(REPLY)
    marks = line_marks(fn, [], suspicious_apis())
    assert marks[2] == [{"kind": "api", "api": "WriteProcessMemory", "family": "thread_inject"}]
    assert marks[3] == [{"kind": "api", "api": "CreateRemoteThread", "family": "thread_inject"}]
    assert marks[4] == []  # GetTickCount is not in a suspicious family
    assert marks[5] == []  # my_send_helper(sendbuf) is not send()
    assert marks[6] == []  # a mention without a call
    assert marks[0] == [] and len(marks) == len(fn.lines)


def test_api_mark_matches_ansi_and_wide_names() -> None:
    fn = DecompiledFunction(
        0x1000,
        "f",
        (
            Line("  RegSetValueExW(hKey,name,0,1,data,len);", (0x1000,)),
            Line("  send(s,buf,len,0); InternetOpenA(agent,0,0,0,0);", (0x1008,)),
        ),
        (),
    )
    marks = line_marks(fn, [], suspicious_apis())
    assert marks[0] == [{"kind": "api", "api": "RegSetValueEx", "family": "registry"}]
    assert marks[1] == [
        {"kind": "api", "api": "send", "family": "net_socket"},
        {"kind": "api", "api": "InternetOpen", "family": "net_http"},
    ]


def test_cache_path_includes_hash(tmp_path: Path) -> None:
    sha = "a" * 64
    path = cache_path(tmp_path, sha, "12.2", "0123456789abcdef", 0x1000)
    assert path == tmp_path / sha / "ghidra-12.2-0123456789abcdef" / "1000.json.gz"
    assert cache_path(tmp_path, sha, "12.2", "ffffffffffffffff", 0x1000) != path
    fn = DecompiledFunction.from_reply(REPLY)
    cache.store(path, fn.to_dict())
    loaded = cache.load(path)
    assert loaded is not None and DecompiledFunction.from_dict(loaded) == fn
