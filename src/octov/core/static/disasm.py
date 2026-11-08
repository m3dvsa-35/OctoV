"""Capstone-based x86/x64 disassembly over a mapped PE image (RVA addressing)."""

from __future__ import annotations

import bisect
from dataclasses import dataclass

import capstone
from capstone import x86

from octov.core.static.pe_parser import PEReport, SectionInfo

MAX_INSN_SIZE = 15


@dataclass(frozen=True)
class Instruction:
    address: int  # RVA
    size: int
    mnemonic: str
    op_str: str
    raw: bytes
    is_jump: bool = False
    is_conditional: bool = False
    is_call: bool = False
    is_ret: bool = False
    is_trap: bool = False  # int3 / hlt / ud2: execution never falls through
    target: int | None = None  # direct branch/call target RVA
    comment: str | None = None  # e.g. resolved import name

    @property
    def end(self) -> int:
        return self.address + self.size

    @property
    def ends_block(self) -> bool:
        return self.is_jump or self.is_ret or self.is_trap

    def text(self) -> str:
        line = f"{self.mnemonic} {self.op_str}".rstrip()
        return f"{line}  ; {self.comment}" if self.comment else line


class ImageView:
    """Read a PE file's bytes by RVA, as the loader would map them (no execution)."""

    def __init__(self, data: bytes, report: PEReport) -> None:
        self.data = data
        self.report = report
        self._sections = sorted(report.sections, key=lambda s: s.virtual_address)
        self._starts = [s.virtual_address for s in self._sections]

    def _section_for(self, rva: int) -> SectionInfo | None:
        idx = bisect.bisect_right(self._starts, rva) - 1
        if idx < 0:
            return None
        sec = self._sections[idx]
        return sec if sec.contains_rva(rva) else None

    def is_executable(self, rva: int) -> bool:
        sec = self._section_for(rva)
        return bool(sec and sec.executable)

    def read(self, rva: int, size: int) -> bytes:
        sec = self._section_for(rva)
        if sec is None:
            return b""
        span = max(sec.virtual_size, sec.raw_size)
        size = min(size, sec.virtual_address + span - rva)
        delta = rva - sec.virtual_address
        raw = b""
        if delta < sec.raw_size:
            start = sec.raw_offset + delta
            raw = self.data[start : start + min(size, sec.raw_size - delta)]
        return raw.ljust(size, b"\x00")


class Disassembler:
    def __init__(self, view: ImageView) -> None:
        self.view = view
        mode = capstone.CS_MODE_64 if view.report.is_64bit else capstone.CS_MODE_32
        self._cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self._cs.detail = True
        self._imports = view.report.import_addresses
        self._image_base = view.report.image_base

    def decode(self, rva: int) -> Instruction | None:
        code = self.view.read(rva, MAX_INSN_SIZE)
        for insn in self._cs.disasm(code, rva, 1):
            return self._convert(insn)
        return None

    def linear(self, rva: int, count: int = 64) -> list[Instruction]:
        out: list[Instruction] = []
        code = self.view.read(rva, count * MAX_INSN_SIZE)
        for insn in self._cs.disasm(code, rva):
            out.append(self._convert(insn))
            if len(out) >= count:
                break
        return out

    def _convert(self, insn: capstone.CsInsn) -> Instruction:
        groups = set(insn.groups)
        is_call = capstone.CS_GRP_CALL in groups
        is_ret = capstone.CS_GRP_RET in groups
        is_jump = capstone.CS_GRP_JUMP in groups and not is_call
        is_conditional = is_jump and insn.mnemonic != "jmp"
        is_trap = insn.mnemonic in ("int3", "hlt", "ud2")

        target: int | None = None
        comment: str | None = None
        if (is_jump or is_call) and insn.operands:
            op = insn.operands[0]
            if op.type == x86.X86_OP_IMM:
                target = op.imm
            elif op.type == x86.X86_OP_MEM:
                slot = self._memory_slot(insn, op)
                if slot is not None:
                    comment = self._imports.get(slot)
        return Instruction(
            address=insn.address,
            size=insn.size,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            raw=bytes(insn.bytes),
            is_jump=is_jump,
            is_conditional=is_conditional,
            is_call=is_call,
            is_ret=is_ret,
            is_trap=is_trap,
            target=target,
            comment=comment,
        )

    def _memory_slot(self, insn: capstone.CsInsn, op: x86.X86Op) -> int | None:
        mem = op.mem
        if mem.index != 0:
            return None
        if mem.base == x86.X86_REG_RIP:
            return int(insn.address + insn.size + mem.disp)
        if mem.base == 0:  # absolute VA (x86)
            return int(mem.disp - self._image_base)
        return None
