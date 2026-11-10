from __future__ import annotations

import dataclasses
import json

from octov.core.ai.bundle import BundleInput, FunctionEvidence, build_bundle
from octov.core.analysis.facts import Evidence, Fact

FACTS = [
    Fact("ioc", "url", "info", "url: http://x.example/gate.php", (Evidence("u", offset=0x600),)),
    Fact(
        "indicator",
        "process_injection_apis",
        "medium",
        "Process injection capability",
        (Evidence("WriteProcessMemory", rva=0x3048), Evidence("CreateRemoteThread", rva=0x3050)),
        mitre=("T1055",),
    ),
]


def fn(
    start: int, score: int = 0, code: str | None = "void f(void)\n{\n  return;\n}"
) -> FunctionEvidence:
    return FunctionEvidence(
        start=start,
        name=f"sub_{start:x}",
        score=score,
        reasons=("calls 2 thread_inject API(s)",) if score else (),
        apis=(("CreateRemoteThread", "thread_inject"), ("GetTickCount", None)),
        callers=((0x900, "entry"),),
        callees=((0x2000, "sub_2000"),),
        strings=("http://x.example/gate.php",),
        code=code,
        code_kind="pseudo_c" if code else None,
    )


def data(**extra: object) -> BundleInput:
    base = BundleInput(
        name="evil.exe",
        sha256="ab" * 32,
        size=4608,
        format="pe",
        bits=64,
        is_dll=False,
        entry_point=0x1000,
        compile_time="2023-09-12T00:00:00",
        signature="none",
        packer=None,
        score=32,
        band="medium",
        facts=FACTS,
        functions=[fn(0x1000, 34), fn(0x1100, 5)],
        iocs=[("url", "http://x.example/gate.php")],
        imports={"thread_inject": ["CreateRemoteThread", "WriteProcessMemory"]},
        sections=[(".text", "R-X", 5.1), (".data", "RW-", 2.0)],
        notes=[(0x1000, "name", "inject_main"), (0x1007, "comment", "writes the payload")],
    )
    return dataclasses.replace(base, **extra)  # type: ignore[arg-type]


def test_bundle_has_sample_findings_functions() -> None:
    doc = build_bundle(data()).doc
    assert doc["sample"]["name"] == "evil.exe" and doc["sample"]["risk_score"] == 32
    assert doc["sample"]["entry_point"] == "0x1000" and doc["sample"]["risk_band"] == "medium"
    # highest severity first
    assert [f["id"] for f in doc["findings"]] == [FACTS[1].id, FACTS[0].id]
    assert doc["findings"][0]["mitre"] == ["T1055"]
    assert doc["findings"][0]["evidence"][0] == {"detail": "WriteProcessMemory", "rva": "0x3048"}
    first = doc["functions"][0]
    assert first["addr"] == "0x1000" and first["score"] == 34
    assert first["apis"] == [
        {"name": "CreateRemoteThread", "family": "thread_inject"},
        {"name": "GetTickCount"},
    ]
    assert first["callers"] == [{"addr": "0x900", "name": "entry"}]
    assert first["code_kind"] == "pseudo_c" and "return;" in first["code"]
    assert doc["iocs"] == [{"type": "url", "value": "http://x.example/gate.php"}]
    assert doc["sections"][0] == {"name": ".text", "perm": "R-X", "entropy": 5.1}
    assert doc["analyst_notes"][0] == {"addr": "0x1000", "kind": "name", "text": "inject_main"}


def test_addresses_are_hex_and_ids_are_citable() -> None:
    bundle = build_bundle(data())
    assert bundle.fact_ids == {f.id for f in FACTS}
    assert bundle.functions == {0x1000, 0x1100}
    assert bundle.iocs == {"http://x.example/gate.php"}


def test_code_is_added_in_rank_order_until_the_budget() -> None:
    big = "x = 1;\n" * 300  # 2100 characters each
    funcs = [fn(0x1000 + i * 0x100, 50 - i, big) for i in range(10)]
    full = build_bundle(data(functions=funcs), budget_chars=100_000)
    assert full.omitted == {"findings": 0, "functions": 0, "code": 0, "iocs": 0}
    tight = build_bundle(data(functions=funcs), budget_chars=9000)
    with_code = [f["addr"] for f in tight.doc["functions"] if "code" in f]
    assert with_code == [f["addr"] for f in tight.doc["functions"]][: len(with_code)]  # by rank
    assert 0 < len(with_code) < 10
    assert tight.omitted["code"] == 10 - len(with_code)
    assert len(tight.doc["functions"]) == 10  # the function table itself always fits
    assert len(tight.text) <= 9000 + 2500
    assert tight.doc["omitted"] == tight.omitted


def test_caps_drop_the_tail_and_count_it() -> None:
    facts = [
        Fact("ioc", "domain", "info", f"domain: d{i}.example", (Evidence("d", offset=i),))
        for i in range(70)
    ]
    funcs = [fn(0x1000 + i * 0x10, 100 - i, None) for i in range(20)]
    iocs = [("domain", f"d{i}.example") for i in range(50)]
    bundle = build_bundle(data(facts=facts, functions=funcs, iocs=iocs), budget_chars=200_000)
    assert len(bundle.doc["findings"]) == 60 and bundle.omitted["findings"] == 10
    assert len(bundle.doc["functions"]) == 13 and bundle.omitted["functions"] == 7
    assert len(bundle.doc["iocs"]) == 40 and bundle.omitted["iocs"] == 10
    assert len(bundle.fact_ids) == 60 and len(bundle.functions) == 13 and len(bundle.iocs) == 40


def test_long_code_and_strings_are_cut() -> None:
    long = fn(0x1000, 9, "y" * 10_000)
    long = dataclasses.replace(long, strings=("s" * 500, *(f"str{i}" for i in range(20))))
    first = build_bundle(data(functions=[long]), budget_chars=100_000).doc["functions"][0]
    assert len(first["code"]) <= 2500 + 20 and first["code"].endswith("… (cut)")
    assert len(first["strings"]) == 8 and len(first["strings"][0]) <= 121


def test_hash_is_stable_and_changes_with_content() -> None:
    one, two = build_bundle(data()), build_bundle(data())
    assert one.hash == two.hash and len(one.hash) == 16 and one.text == two.text
    renamed = build_bundle(data(notes=[(0x1000, "name", "other")]))
    assert renamed.hash != one.hash


def test_text_round_trips_as_json() -> None:
    bundle = build_bundle(data(name="şəkil.exe"))
    assert json.loads(bundle.text) == bundle.doc
    assert "şəkil.exe" in bundle.text  # readable in the preview, not \\u escapes


def test_no_raw_bytes_or_paths() -> None:
    bundle = build_bundle(data(name=r"C:\Users\someone\Desktop\case 7\evil.exe"))
    assert bundle.doc["sample"]["name"] == "evil.exe"
    assert "someone" not in bundle.text and "Desktop" not in bundle.text
