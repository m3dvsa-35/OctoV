"""Search inside a sample: byte patterns with wildcards, instruction text, immediate values."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from octov.core.static.cfg import Function
from octov.core.static.disasm import Instruction

_PATTERN_TOKEN = re.compile(r"[0-9a-fA-F]{2}|\?\??")
_NUMBER_TOKEN = re.compile(r"0x[0-9a-f]+|\b\d+\b")
_SPACES = re.compile(r"\s+")
MAX_PATTERN = 256  # bytes; longer patterns make the scan cost file size x pattern


@dataclass(frozen=True)
class InsnHit:
    address: int
    function: int
    text: str


def parse_pattern(text: str) -> tuple[int | None, ...]:
    """``"4D 5A ?? 00"`` -> bytes with ``None`` for a wildcard; spaces are optional."""
    compact = _SPACES.sub("", text)
    tokens = _PATTERN_TOKEN.findall(compact)
    if not tokens or "".join(tokens) != compact:
        raise ValueError("pattern must be hex bytes and ?? wildcards, e.g. 4D 5A ?? 00")
    pattern = tuple(None if tok.startswith("?") else int(tok, 16) for tok in tokens)
    if all(b is None for b in pattern):
        raise ValueError("pattern needs at least one fixed byte")
    if len(pattern) > MAX_PATTERN:
        raise ValueError(f"pattern is longer than {MAX_PATTERN} bytes")
    return pattern


def parse_number(text: str) -> int:
    """``0x10``, ``10h`` or decimal ``16``."""
    value = text.strip().lower()
    try:
        if value.startswith("0x"):
            return int(value[2:], 16)
        if value.endswith("h"):
            return int(value[:-1], 16)
        if value.isdigit():
            return int(value)
    except ValueError:
        pass
    raise ValueError("value must be a number such as 0x10, 10h or 16")


def search_bytes(
    data: bytes, pattern: tuple[int | None, ...], limit: int
) -> tuple[list[int], bool]:
    """File offsets of every match (overlapping ones too); ``True`` when cut at ``limit``."""
    body = b"".join(b"." if b is None else re.escape(bytes([b])) for b in pattern)
    regex = re.compile(b"(?=" + body + b")", re.DOTALL)
    offsets: list[int] = []
    for match in regex.finditer(data):
        if len(offsets) >= limit:
            return offsets, True
        offsets.append(match.start())
    return offsets, False


def _instructions(functions: Mapping[int, Function]) -> Iterator[tuple[int, Instruction]]:
    seen: set[int] = set()  # a block shared by two functions (tail jump) is listed once
    for start in sorted(functions):
        fn = functions[start]
        for block_start in sorted(fn.blocks):
            for insn in fn.blocks[block_start].instructions:
                if insn.address not in seen:
                    seen.add(insn.address)
                    yield start, insn


def search_text(
    functions: Mapping[int, Function], query: str, limit: int
) -> tuple[list[InsnHit], bool]:
    """Case-insensitive substring of ``mnemonic operands ; comment``; spaces are collapsed."""
    needle = _SPACES.sub(" ", query.strip().lower())
    hits: list[InsnHit] = []
    if not needle:
        return hits, False
    for start, insn in _instructions(functions):
        text = insn.text()
        if needle in _SPACES.sub(" ", text.lower()):
            if len(hits) >= limit:
                return hits, True
            hits.append(InsnHit(insn.address, start, text))
    return hits, False


def _numbers(op_str: str) -> Iterator[int]:
    for token in _NUMBER_TOKEN.findall(op_str.lower()):
        yield int(token, 16) if token.startswith("0x") else int(token)


def search_immediate(
    functions: Mapping[int, Function], value: int, limit: int
) -> tuple[list[InsnHit], bool]:
    """Instructions with an operand number, branch target or data reference equal to ``value``."""
    hits: list[InsnHit] = []
    for start, insn in _instructions(functions):
        if insn.target == value or insn.data_ref == value or value in _numbers(insn.op_str):
            if len(hits) >= limit:
                return hits, True
            hits.append(InsnHit(insn.address, start, insn.text()))
    return hits, False
