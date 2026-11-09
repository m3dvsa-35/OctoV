from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from octov.core.analysis.iocs import Ioc
from octov.core.analysis.strings import FoundString, classify
from octov.ext.floss import floss_command, floss_facts, merge_strings, parse_floss
from octov.ext.runner import EngineError

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "floss" / "synthetic_stack.json"
BASE = 0x140000000
URL = "http://x.example/gate.php"


def _doc() -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return doc


def _recovered(value: str, origin: str = "stack", function: int = 0x1000) -> FoundString:
    return FoundString(value, "ascii", -1, function, None, classify(value), origin, function)  # type: ignore[arg-type]


def test_command_shape(tmp_path: Path) -> None:
    cmd = floss_command(tmp_path / "s.exe", raw=False, bits=64)
    assert cmd[:3] == [sys.executable, "-m", "floss.main"]
    assert "-j" in cmd
    only = cmd.index("--only")
    assert cmd[only + 1 : only + 4] == ["stack", "tight", "decoded"]
    assert cmd[-2:] == ["--", str(tmp_path / "s.exe")]
    raw = floss_command(tmp_path / "s.bin", raw=True, bits=32)
    assert raw[raw.index("--format") + 1] == "sc32"


def test_stack_string_recovered() -> None:
    strings = parse_floss(_doc(), BASE, 0x10000)
    assert [s.value for s in strings] == [URL]
    s = strings[0]
    assert (s.origin, s.function, s.rva, s.offset) == ("stack", 0x1000, 0x1000, -1)
    assert s.category == "url"


def test_tight_and_decoded_strings() -> None:
    doc = copy.deepcopy(_doc())
    doc["strings"]["tight_strings"] = [
        {**doc["strings"]["stack_strings"][0], "string": "Global\\mtx-1", "function": BASE + 0x1100}
    ]
    doc["strings"]["decoded_strings"] = [
        {
            "address": 0,
            "address_type": "HEAP",
            "string": "cmd.exe /c whoami",
            "encoding": "ASCII",
            "decoded_at": BASE + 0x1234,
            "decoding_routine": BASE + 0x1200,
        }
    ]
    by_value = {s.value: s for s in parse_floss(doc, BASE, 0x10000)}
    assert by_value["Global\\mtx-1"].origin == "tight"
    assert by_value["Global\\mtx-1"].function == 0x1100
    decoded = by_value["cmd.exe /c whoami"]
    assert (decoded.origin, decoded.function, decoded.rva) == ("decoded", 0x1200, 0x1234)


def test_addresses_outside_image_have_no_function() -> None:
    doc = copy.deepcopy(_doc())
    doc["strings"]["stack_strings"][0]["function"] = BASE - 1
    s = parse_floss(doc, BASE, 0x10000)[0]
    assert s.function is None and s.rva is None


def test_static_duplicates_dropped() -> None:
    static = [FoundString(URL, "ascii", 0x400, 0x2000, ".data", "url")]
    merged = merge_strings(static, [_recovered(URL), _recovered("other value")])
    assert [s.value for s in merged] == [URL, "other value"]
    assert merged[0].origin == "static"


def test_obfuscated_strings_threshold() -> None:
    four = [_recovered(f"value {i}", function=0x1000 + i) for i in range(4)]
    assert floss_facts(four, []) == []
    five = [*four, _recovered("value 5", function=0x2000)]
    facts = floss_facts(five, [])
    assert [(f.kind, f.severity, f.source_id) for f in facts] == [
        ("obfuscated_strings", "low", "floss")
    ]
    assert sorted(e.rva for e in facts[0].evidence) == [0x1000, 0x1001, 0x1002, 0x1003, 0x2000]


def test_hidden_ioc_is_one_fact() -> None:
    recovered = [_recovered(URL), _recovered("http://y.example/a", function=0x3000)]
    iocs = [
        Ioc("url", URL, (), None),
        Ioc("domain", "x.example", (), None),
        Ioc("url", "http://y.example/a", (), None),
    ]
    facts = [f for f in floss_facts(recovered, iocs) if f.kind == "hidden_ioc"]
    assert len(facts) == 1
    fact = facts[0]
    assert (fact.severity, fact.source_id) == ("medium", "floss")
    assert {e.value for e in fact.evidence} == {URL, "x.example", "http://y.example/a"}
    assert {e.rva for e in fact.evidence if e.value == "http://y.example/a"} == {0x3000}


def test_unknown_schema_rejected() -> None:
    doc = copy.deepcopy(_doc())
    doc["metadata"]["version"] = "2.3.0"
    with pytest.raises(EngineError) as err:
        parse_floss(doc, BASE, 0x10000)
    assert err.value.kind == "bad_output"
    with pytest.raises(EngineError):
        parse_floss({"metadata": {"version": "3.2.0"}, "strings": []}, BASE, 0x10000)


def _floss_installed() -> bool:
    import importlib.util

    return importlib.util.find_spec("floss") is not None


@pytest.mark.skipif(not _floss_installed(), reason="FLOSS not installed")
def test_integration_real_floss_recovers_stack_string(tmp_path: Path) -> None:
    import threading

    from octov.ext.runner import parse_json, run_engine
    from tests.samples.builder import stack_string_pe

    sample = tmp_path / "stack.exe"
    sample.write_bytes(stack_string_pe(URL))
    run = run_engine(
        floss_command(sample, raw=False, bits=64),
        timeout_s=300,
        max_memory_mb=4096,
        cancel=threading.Event(),
    )
    assert URL in [s.value for s in parse_floss(parse_json(run), BASE, 0x10000)]
