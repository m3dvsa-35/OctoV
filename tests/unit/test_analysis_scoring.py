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
