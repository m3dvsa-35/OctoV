"""Cross-references: who calls/jumps to an address, who reads a string or an import."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

from octov.core.static.cfg import Function

XrefKind = Literal["call", "jump", "data", "import"]


@dataclass(frozen=True)
class Xref:
    src: int
    dst: int
    kind: XrefKind
    func: int | None


class XrefIndex:
    def __init__(self, xrefs: list[Xref], import_addresses: dict[int, str]) -> None:
        self._imports = import_addresses
        self._to: dict[int, list[Xref]] = defaultdict(list)
        self._from: dict[int, list[Xref]] = defaultdict(list)
        for x in xrefs:
            self._to[x.dst].append(x)
            if x.func is not None:
                self._from[x.func].append(x)

    @classmethod
    def build(cls, functions: dict[int, Function], import_addresses: dict[int, str]) -> XrefIndex:
        seen: set[tuple[int, int, str]] = set()
        xrefs: list[Xref] = []

        def add(src: int, dst: int, kind: XrefKind, func: int) -> None:
            if (src, dst, kind) not in seen:
                seen.add((src, dst, kind))
                xrefs.append(Xref(src, dst, kind, func))

        slots = {name: rva for rva, name in import_addresses.items()}
        for start, fn in functions.items():
            for block in fn.blocks.values():
                for insn in block.instructions:
                    if insn.target is not None and (insn.is_call or insn.is_jump):
                        add(insn.address, insn.target, "call" if insn.is_call else "jump", start)
                    elif insn.comment and insn.comment in slots:
                        add(insn.address, slots[insn.comment], "import", start)
                    if insn.data_ref is not None:
                        kind: XrefKind = "import" if insn.data_ref in import_addresses else "data"
                        add(insn.address, insn.data_ref, kind, start)
        xrefs.sort(key=lambda x: (x.dst, x.src))
        return cls(xrefs, import_addresses)

    def to(self, dst: int) -> list[Xref]:
        return list(self._to.get(dst, []))

    def from_function(self, start: int) -> list[Xref]:
        return sorted(self._from.get(start, []), key=lambda x: x.src)

    def imports_called(self, start: int) -> list[str]:
        """``dll!func`` names a function calls or references through the IAT."""
        return [self._imports[x.dst] for x in self.from_function(start) if x.kind == "import"]
