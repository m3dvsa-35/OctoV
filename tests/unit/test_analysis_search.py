from __future__ import annotations

import pytest

from octov.core.analysis.search import (
    InsnHit,
    parse_number,
    parse_pattern,
    search_bytes,
    search_immediate,
    search_text,
)
from octov.core.static.cfg import BasicBlock, Function
from octov.core.static.disasm import Instruction


def insn(address: int, mnemonic: str, ops: str = "", **extra: object) -> Instruction:
    return Instruction(address, 4, mnemonic, ops, b"\x90" * 4, **extra)  # type: ignore[arg-type]


FUNCTIONS = {
    0x1000: Function(
        0x1000,
        {
            0x1000: BasicBlock(
                0x1000,
                [
                    insn(0x1000, "mov", "eax, 0x10"),
                    insn(0x1004, "xor", "ecx, 0x100"),
                    insn(
                        0x1008,
                        "call",
                        "qword ptr [rip + 0x2000]",
                        comment="kernel32.dll!VirtualAlloc",
                    ),
                    insn(0x100C, "lea", "rdx, [rip + 0x1ff0]", data_ref=0x3000),
                ],
            )
        },
        [],
    ),
    0x2000: Function(
        0x2000,
        {
            0x2000: BasicBlock(
                0x2000,
                [
                    insn(0x2000, "call", "0x1000", is_call=True, target=0x1000),
                    insn(0x2004, "add", "rsp, 16"),
                    insn(0x2008, "MOV", "EAX, 0X10"),
                ],
            )
        },
        [0x1000],
    ),
}


def test_parse_pattern_bytes_and_wildcards() -> None:
    assert parse_pattern("4d5a ?? 00") == (0x4D, 0x5A, None, 0x00)
    assert parse_pattern(" 4D 5A ? 00 ") == (0x4D, 0x5A, None, 0x00)
    assert parse_pattern("4D5A??00") == (0x4D, 0x5A, None, 0x00)


@pytest.mark.parametrize("bad", ["", "   ", "4d5", "4d 5", "zz", "4d-5a", "?? ??", "?", "0x4d"])
def test_parse_pattern_rejects_bad_input(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_pattern(bad)


def test_search_bytes_wildcard_and_overlapping_hits() -> None:
    data = b"\x00MZ\x90\x00--MZ\x91\x00--aaaa"
    assert search_bytes(data, parse_pattern("4d 5a ?? 00"), 10) == ([1, 7], False)
    assert search_bytes(data, parse_pattern("61 61"), 10) == ([13, 14, 15], False)  # overlapping
    assert search_bytes(data, parse_pattern("ff ee"), 10) == ([], False)
    assert search_bytes(b"\n\x41", parse_pattern("?? 41"), 10) == ([0], False)  # ?? is any byte


def test_search_bytes_limit_truncates() -> None:
    assert search_bytes(b"\xcc" * 100, parse_pattern("cc"), 5) == ([0, 1, 2, 3, 4], True)
    assert search_bytes(b"\xcc" * 5, parse_pattern("cc"), 5) == ([0, 1, 2, 3, 4], False)


def test_search_bytes_treats_regex_specials_literally() -> None:
    data = b"abc.*[xyz"
    assert search_bytes(data, parse_pattern("2e 2a 5b"), 10) == ([3], False)


def test_search_text_case_insensitive_and_comment() -> None:
    hits, truncated = search_text(FUNCTIONS, "MOV  eax", 10)
    assert not truncated
    assert hits == [
        InsnHit(0x1000, 0x1000, "mov eax, 0x10"),
        InsnHit(0x2008, 0x2000, "MOV EAX, 0X10"),
    ]
    assert [h.address for h in search_text(FUNCTIONS, "virtualalloc", 10)[0]] == [0x1008]
    assert search_text(FUNCTIONS, "   ", 10) == ([], False)
    assert search_text(FUNCTIONS, "0x", 2) == (
        [InsnHit(0x1000, 0x1000, "mov eax, 0x10"), InsnHit(0x1004, 0x1000, "xor ecx, 0x100")],
        True,
    )


def test_search_immediate_matches_operand_target_and_data_ref() -> None:
    assert [h.address for h in search_immediate(FUNCTIONS, 0x10, 10)[0]] == [0x1000, 0x2004, 0x2008]
    assert [h.address for h in search_immediate(FUNCTIONS, 0x1000, 10)[0]] == [0x2000]  # target
    assert [h.address for h in search_immediate(FUNCTIONS, 0x3000, 10)[0]] == [0x100C]  # data ref
    assert search_immediate(FUNCTIONS, 0x10, 1) == (
        [InsnHit(0x1000, 0x1000, "mov eax, 0x10")],
        True,
    )


def test_search_immediate_does_not_match_substring() -> None:
    hits = [h.address for h in search_immediate(FUNCTIONS, 0x100, 10)[0]]
    assert hits == [0x1004]
    assert search_immediate(FUNCTIONS, 0x1, 10) == ([], False)


@pytest.mark.parametrize(
    ("text", "value"), [("0x10", 16), ("10h", 16), ("16", 16), (" 0XFF ", 255), ("0", 0)]
)
def test_parse_number(text: str, value: int) -> None:
    assert parse_number(text) == value


@pytest.mark.parametrize("bad", ["", "x", "0x", "12g", "-1", "1 2"])
def test_parse_number_rejects_bad_input(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_number(bad)
