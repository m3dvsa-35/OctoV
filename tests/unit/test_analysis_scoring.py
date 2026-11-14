from __future__ import annotations

from octov.core.analysis.facts import Evidence, Fact
from octov.core.analysis.scoring import rank_functions, risk_score
from octov.core.analysis.strings import FoundString
from octov.core.analysis.xrefs import Xref, XrefIndex
from octov.core.static.cfg import BasicBlock, Function
from octov.core.static.disasm import Instruction


def _fact(sev: str, n: int, rva: int = 0x1000, conf: float = 1.0) -> Fact:
    return Fact("rule", f"R{n}", sev, f"rule {n}", (Evidence("x", rva=rva),), confidence=conf)  # type: ignore[arg-type]


def test_four_high_facts_cap_at_100() -> None:
    score = risk_score([_fact("high", i) for i in range(4)], {})
    assert (score.score, score.band) == (100, "high")


def test_two_medium_facts_are_low_band() -> None:
    score = risk_score([_fact("medium", 1), _fact("medium", 2)], {})
    assert (score.score, score.band) == (24, "low")


def test_false_positive_contributes_zero_but_is_listed() -> None:
    high = _fact("high", 1)
    score = risk_score([high, _fact("medium", 2)], {high.id: "false_positive"})
    assert score.score == 12
    assert (high.id, 0) in score.contributions


def test_benign_verdict_also_zero_and_confirmed_counts() -> None:
    a, b = _fact("high", 1), _fact("high", 2)
    assert risk_score([a, b], {a.id: "benign", b.id: "confirmed"}).score == 30


def test_confidence_scales_points() -> None:
    assert risk_score([_fact("high", 1, conf=0.5)], {}).score == 15


def test_bands() -> None:
    facts = [_fact("medium", 1), _fact("medium", 2), _fact("low", 3), _fact("low", 4)]
    assert risk_score(facts, {}).score == 32
    assert risk_score(facts, {}).band == "medium"


def _fn(start: int, size: int) -> Function:
    insn = Instruction(start, size, "nop", "", b"\x90" * size)
    return Function(start, {start: BasicBlock(start, [insn])}, [])


def test_ranking_puts_injector_with_url_first() -> None:
    functions = {0x1000: _fn(0x1000, 0x20), 0x2000: _fn(0x2000, 0x20)}
    imports = {0x9000: "kernel32.dll!WriteProcessMemory", 0x9008: "kernel32.dll!CreateRemoteThread"}
    xrefs = XrefIndex(
        [
            Xref(0x1004, 0x9000, "import", 0x1000),
            Xref(0x1008, 0x9008, "import", 0x1000),
            Xref(0x100C, 0x5000, "data", 0x1000),
        ],
        imports,
    )
    url = FoundString("http://x.example/gate.php", "ascii", 0x400, 0x5000, ".data", "url")
    facts = [_fact("high", 1, rva=0x1010)]
    ranked = rank_functions(functions, xrefs, facts, [url], {0x1000: "thread_inject_1000"})
    assert [r.start for r in ranked] == [0x1000]
    top = ranked[0]
    assert top.name == "thread_inject_1000" and top.score > 0
    joined = " ".join(top.reasons)
    assert "R1" in joined and "thread_inject" in joined and "http://x.example/gate.php" in joined


def test_ranking_skips_zero_score_and_caps_at_20() -> None:
    functions = {0x1000 + 0x100 * i: _fn(0x1000 + 0x100 * i, 0x10) for i in range(30)}
    facts = [_fact("low", i, rva=0x1000 + 0x100 * i) for i in range(25)]
    ranked = rank_functions(functions, XrefIndex([], {}), facts, [], {})
    assert len(ranked) == 20 and all(r.score > 0 for r in ranked)
    assert ranked[0].name.startswith("sub_")


def test_repeated_detector_counts_once_but_every_fact_is_listed() -> None:
    blobs = [
        Fact("embedded_payload", "high_entropy", "low", f"blob {i}", (Evidence("b", offset=i),))
        for i in range(20)
    ]
    score = risk_score(blobs, {})
    assert score.score == 4
    assert len(score.contributions) == 20
    assert sorted(p for _, p in score.contributions) == [0] * 19 + [4]


def test_crypto_constants_count_as_one_signal() -> None:
    tables = [
        Fact("crypto_constant", name, "low", name, (Evidence("t", rva=0x2000 + i),))
        for i, name in enumerate(("AES Te0", "CRC32 table", "SHA-1 init"))
    ]
    assert risk_score(tables, {}).score == 4


def test_false_positive_on_counted_duplicate_lets_the_next_one_count() -> None:
    a = Fact("indicator", "virtual_size_inflated", "low", "a", (Evidence("a", rva=0x1000),))
    b = Fact("indicator", "virtual_size_inflated", "low", "b", (Evidence("b", rva=0x2000),))
    assert risk_score([a, b], {a.id: "false_positive"}).score == 4
    assert risk_score([a, b], {a.id: "false_positive", b.id: "benign"}).score == 0


def test_distinct_detectors_still_add_up() -> None:
    assert risk_score([_fact("medium", 1), _fact("medium", 2), _fact("low", 3)], {}).score == 28


def test_capa_reason_in_ranking() -> None:
    from octov.core.analysis.xrefs import XrefIndex

    fn = _fn(0x1000, 0x20)
    fact = Fact("capability", "contain loop", "info", "contain loop", (Evidence("f", rva=0x1000),))
    medium = Fact(
        "capability", "inject thread", "medium", "inject thread", (Evidence("f", rva=0x1000),)
    )
    xrefs = XrefIndex.build({0x1000: fn}, {})
    only_info = rank_functions({0x1000: fn}, xrefs, [fact], [], {})
    assert only_info == []  # info adds no points, so the function is not ranked on it
    ranked = rank_functions({0x1000: fn}, xrefs, [fact, medium], [], {})
    assert "capa: contain loop" in ranked[0].reasons
    assert "capa: inject thread" in ranked[0].reasons
    assert ranked[0].score == 20


def _injector() -> tuple[dict[int, Function], XrefIndex]:
    functions = {0x1000: _fn(0x1000, 0x20)}
    imports = {0x9000: "kernel32.dll!WriteProcessMemory", 0x9008: "kernel32.dll!CreateRemoteThread"}
    refs = [Xref(0x1004, 0x9000, "import", 0x1000), Xref(0x1008, 0x9008, "import", 0x1000)]
    return functions, XrefIndex(refs, imports)


def test_library_functions_are_left_out_of_the_ranking() -> None:
    functions, xrefs = _injector()
    low = [_fact("low", 1, rva=0x1010)]
    assert [r.start for r in rank_functions(functions, xrefs, low, [], {})] == [0x1000]
    assert rank_functions(functions, xrefs, low, [], {}, library={0x1000}) == []


def test_library_function_with_a_medium_fact_stays_ranked() -> None:
    functions, xrefs = _injector()
    for severity in ("medium", "high"):
        facts = [_fact(severity, 1, rva=0x1010)]
        ranked = rank_functions(functions, xrefs, facts, [], {}, library={0x1000})
        assert [r.start for r in ranked] == [0x1000]
