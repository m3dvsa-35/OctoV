"""Recursive-descent function discovery and basic-block control-flow graphs."""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Any, Literal

from octov.core.static.disasm import Disassembler, Instruction
from octov.core.static.pe_parser import PEReport

EdgeKind = Literal["fallthrough", "jump", "true", "false"]
MAX_BLOCK_INSNS = 4096
MAX_FUNCTION_BLOCKS = 10_000


@dataclass(frozen=True)
class Edge:
    target: int
    kind: EdgeKind


@dataclass
class BasicBlock:
    start: int
    instructions: list[Instruction]
    successors: list[Edge] = field(default_factory=list)
    indirect: bool = False  # ends in an indirect jump (switch / tail call via register)

    @property
    def end(self) -> int:
        return self.instructions[-1].end if self.instructions else self.start


@dataclass
class Function:
    start: int
    blocks: dict[int, BasicBlock]
    calls: list[int]

    @property
    def size(self) -> int:
        return sum(b.end - b.start for b in self.blocks.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "calls": self.calls,
            "blocks": [
                {
                    "start": b.start,
                    "end": b.end,
                    "indirect": b.indirect,
                    "successors": [{"target": e.target, "kind": e.kind} for e in b.successors],
                    "instructions": [
                        {"address": i.address, "text": i.text(), "bytes": i.raw.hex()}
                        for i in b.instructions
                    ],
                }
                for b in sorted(self.blocks.values(), key=lambda b: b.start)
            ],
        }


def _decode_block(dis: Disassembler, start: int, stop_at: set[int]) -> BasicBlock:
    """Decode linearly from ``start`` until a block terminator or a known leader."""
    insns: list[Instruction] = []
    addr = start
    while len(insns) < MAX_BLOCK_INSNS:
        if insns and addr in stop_at:
            return BasicBlock(start, insns, [Edge(addr, "fallthrough")])
        insn = dis.decode(addr)
        if insn is None:
            break
        insns.append(insn)
        addr = insn.end
        if insn.ends_block:
            break
    block = BasicBlock(start, insns)
    last = insns[-1] if insns else None
    if last is None:
        return block
    if last.is_jump:
        if last.target is None:
            block.indirect = True
        elif last.is_conditional:
            block.successors = [Edge(last.target, "true"), Edge(last.end, "false")]
        else:
            block.successors = [Edge(last.target, "jump")]
    elif not (last.is_ret or last.is_trap):
        block.successors = [Edge(last.end, "fallthrough")]
    return block


def _split(blocks: dict[int, BasicBlock], at: int) -> bool:
    """Split the block containing ``at`` (if ``at`` is mid-block). Returns True if split."""
    starts = sorted(blocks)
    idx = bisect.bisect_right(starts, at) - 1
    if idx < 0:
        return False
    block = blocks[starts[idx]]
    if block.start == at or not (block.start < at < block.end):
        return False
    cut = next((i for i, insn in enumerate(block.instructions) if insn.address == at), None)
    if cut is None:  # overlapping/misaligned instruction stream: leave as is
        return False
    tail = BasicBlock(at, block.instructions[cut:], block.successors, block.indirect)
    block.instructions = block.instructions[:cut]
    block.successors = [Edge(at, "fallthrough")]
    block.indirect = False
    blocks[at] = tail
    return True


def build_function(dis: Disassembler, start: int) -> Function:
    blocks: dict[int, BasicBlock] = {}
    calls: list[int] = []
    work = [start]
    while work and len(blocks) < MAX_FUNCTION_BLOCKS:
        leader = work.pop()
        if leader in blocks or _split(blocks, leader):
            continue
        if not dis.view.is_executable(leader):
            continue
        block = _decode_block(dis, leader, set(blocks))
        if not block.instructions:
            continue
        blocks[leader] = block
        for insn in block.instructions:
            if insn.is_call and insn.target is not None and insn.target not in calls:
                calls.append(insn.target)
        work.extend(e.target for e in block.successors)
    return Function(start, blocks, calls)


def discover_functions(
    dis: Disassembler, report: PEReport, max_functions: int = 20_000
) -> dict[int, Function]:
    """Functions reachable from the entry point, exports, .pdata starts and direct calls."""
    seeds = [report.entry_point, *report.export_rvas.values(), *report.function_starts]
    functions: dict[int, Function] = {}
    queue = [s for s in dict.fromkeys(seeds) if s and dis.view.is_executable(s)]
    while queue and len(functions) < max_functions:
        start = queue.pop()
        if start in functions:
            continue
        fn = build_function(dis, start)
        if not fn.blocks:
            continue
        functions[start] = fn
        queue.extend(t for t in fn.calls if t not in functions and dis.view.is_executable(t))
    return functions
