"""Capstone-based x86/x64 disassembly over a code view.

A view is either a mapped PE image (:class:`ImageView`, RVA addressing) or a
raw blob such as shellcode (:class:`RawView`, offset addressing).
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from typing import Protocol

import capstone

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
    data_ref: int | None = None  # RVA referenced by a memory/immediate operand (non-branch)

    @property
    def end(self) -> int:
        return self.address + self.size

    @property
    def ends_block(self) -> bool:
        return self.is_jump or self.is_ret or self.is_trap

    def text(self) -> str:
        line = f"{self.mnemonic} {self.op_str}".rstrip()
        return f"{line}  ; {self.comment}" if self.comment else line


class CodeView(Protocol):
    is_64bit: bool
    image_base: int
    import_addresses: dict[int, str]

    def read(self, rva: int, size: int) -> bytes: ...

    def is_executable(self, rva: int) -> bool: ...

    def contains(self, rva: int) -> bool: ...


class RawView:
    """A raw code blob (e.g. extracted shellcode) addressed by offset from ``base``."""

    def __init__(self, data: bytes, bits: int = 64, base: int = 0) -> None:
        if bits not in (32, 64):
            raise ValueError("bits must be 32 or 64")
        self.data = data
        self.is_64bit = bits == 64
        self.image_base = base
        self.import_addresses: dict[int, str] = {}

    def is_executable(self, rva: int) -> bool:
        return 0 <= rva - self.image_base < len(self.data)

    def contains(self, rva: int) -> bool:
        return self.is_executable(rva)

    def read(self, rva: int, size: int) -> bytes:
        off = rva - self.image_base
        if not 0 <= off < len(self.data):
            return b""
        return self.data[off : off + size]


class ImageView:
    """Read a PE file's bytes by RVA, as the loader would map them (no execution)."""

    def __init__(self, data: bytes, report: PEReport) -> None:
        self.data = data
        self.report = report
        self.is_64bit = report.is_64bit
        self.image_base = report.image_base
        self.import_addresses = report.import_addresses
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

    def contains(self, rva: int) -> bool:
        return self._section_for(rva) is not None

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

    def read_raw(self, rva: int, size: int) -> bytes:
        """Like ``read`` but only bytes the file really has: no zero padding for the virtual
        part of a section (signature matching must not see padding as code)."""
        sec = self._section_for(rva)
        if sec is None:
            return b""
        delta = rva - sec.virtual_address
        if delta >= sec.raw_size:
            return b""
        start = sec.raw_offset + delta
        return self.data[start : start + min(size, sec.raw_size - delta)]


_RIP_SLOT = re.compile(r"\[rip ([+-]) 0x([0-9a-f]+)\]")
_ABS_SLOT = re.compile(r"(?:ptr |^)\[0x([0-9a-f]+)\]")
_HEX_IMM = re.compile(r"0x[0-9a-f]{5,16}")
_RETURNS = frozenset({"ret", "retf", "iret", "iretd", "iretq", "sysret", "sysexit"})
_TRAPS = frozenset({"int3", "hlt", "ud2"})


class Disassembler:
    """Decodes with Capstone's lightweight API (no per-operand detail objects).

    Control-flow facts are derived from the mnemonic and operand text, which is
    several times faster than Capstone's detail mode from Python.
    """

    def __init__(self, view: CodeView) -> None:
        self.view = view
        mode = capstone.CS_MODE_64 if view.is_64bit else capstone.CS_MODE_32
        self._cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        self._imports = view.import_addresses
        self._image_base = view.image_base

    def decode(self, rva: int) -> Instruction | None:
        code = self.view.read(rva, MAX_INSN_SIZE)
        for address, size, mnemonic, op_str in self._cs.disasm_lite(code, rva, 1):
            return self._convert(address, size, mnemonic, op_str, code[:size])
        return None

    def linear(self, rva: int, count: int = 64) -> list[Instruction]:
        out: list[Instruction] = []
        code = self.view.read(rva, count * MAX_INSN_SIZE)
        for address, size, mnemonic, op_str in self._cs.disasm_lite(code, rva):
            off = address - rva
            out.append(self._convert(address, size, mnemonic, op_str, code[off : off + size]))
            if len(out) >= count:
                break
        return out

    def _convert(
        self, address: int, size: int, mnemonic: str, op_str: str, raw: bytes
    ) -> Instruction:
        # Strip prefixes such as "bnd jmp" / "notrack jmp".
        base = mnemonic.rsplit(" ", 1)[-1]
        is_call = base in ("call", "lcall")
        is_ret = base in _RETURNS
        is_jump = base == "ljmp" or base.startswith(("j", "loop"))
        is_conditional = is_jump and base not in ("jmp", "ljmp")

        target: int | None = None
        comment: str | None = None
        if is_jump or is_call:
            if op_str and not any(c in op_str for c in " [:"):
                try:  # Capstone prints small immediates in decimal, others as 0x...
                    target = int(op_str, 0)
                except ValueError:  # register operand: indirect
                    target = None
            if target is None:
                slot = self._memory_slot(address, size, op_str)
                if slot is not None:
                    comment = self._imports.get(slot)
        data_ref = None if (is_jump or is_call) else self._data_ref(address, size, op_str)
        return Instruction(
            address=address,
            size=size,
            mnemonic=mnemonic,
            op_str=op_str,
            raw=raw,
            is_jump=is_jump,
            is_conditional=is_conditional,
            is_call=is_call,
            is_ret=is_ret,
            is_trap=base in _TRAPS,
            target=target,
            comment=comment,
            data_ref=data_ref,
        )

    def _data_ref(self, address: int, size: int, op_str: str) -> int | None:
        """RVA inside the image that a non-branch operand points to, if any."""
        slot = self._memory_slot(address, size, op_str)
        if slot is not None and self.view.contains(slot):
            return slot
        if self._image_base:  # absolute VAs as immediates (common in x86 code)
            for token in _HEX_IMM.findall(op_str):
                rva = int(token, 16) - self._image_base
                if rva > 0 and self.view.contains(rva):
                    return rva
        return None

    def _memory_slot(self, address: int, size: int, op_str: str) -> int | None:
        m = _RIP_SLOT.search(op_str)
        if m:
            disp = int(m.group(2), 16)
            return address + size + (disp if m.group(1) == "+" else -disp)
        m = _ABS_SLOT.search(op_str)
        if m:  # absolute VA (x86)
            return int(m.group(1), 16) - self._image_base
        return None
