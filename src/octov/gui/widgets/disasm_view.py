"""Read-only disassembly listing with address navigation."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor, QMouseEvent, QTextCursor, QTextFormat
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit

from octov.core.static.cfg import Function
from octov.core.static.disasm import Instruction


class DisassemblyView(QPlainTextEdit):
    """Shows a function block by block. Double-click a branch/call to follow it."""

    addressActivated = Signal(int)  # noqa: N815 (Qt signal naming)

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._line_insn: dict[int, Instruction] = {}
        self._addr_line: dict[int, int] = {}
        self._current: int | None = None
        self.highlight_color = QColor("#2f81f7")

    def set_function(self, fn: Function) -> None:
        self.set_instructions(
            [(b.start, b.instructions) for b in sorted(fn.blocks.values(), key=lambda b: b.start)],
            title=f"sub_{fn.start:x}",
        )

    def set_instructions(
        self, groups: list[tuple[int, list[Instruction]]], title: str | None = None
    ) -> None:
        lines: list[str] = []
        self._line_insn.clear()
        self._addr_line.clear()
        if title:
            lines += [f"; ---- {title} ----"]
        for start, insns in groups:
            lines.append(f"loc_{start:x}:")
            for insn in insns:
                self._line_insn[len(lines)] = insn
                self._addr_line.setdefault(insn.address, len(lines))
                raw = insn.raw.hex(" ")
                raw = raw if len(raw) <= 23 else raw[:21] + ".."
                lines.append(f"  {insn.address:08x}  {raw:<24} {insn.text()}")
            lines.append("")
        self.setPlainText("\n".join(lines))
        self._current = None

    def current_address(self) -> int | None:
        return self._current

    def highlight(self, rva: int) -> bool:
        line = self._addr_line.get(rva)
        if line is None:
            # Address inside an instruction: pick the instruction covering it.
            line = next((n for n, i in self._line_insn.items() if i.address <= rva < i.end), None)
        if line is None:
            return False
        self._current = self._line_insn[line].address
        block = self.document().findBlockByNumber(line)
        cursor = QTextCursor(block)
        self.setTextCursor(cursor)
        self.centerCursor()
        sel = QTextEdit.ExtraSelection()
        sel.format.setBackground(self.highlight_color.darker(250))
        sel.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
        sel.cursor = cursor
        self.setExtraSelections([sel])
        return True

    def activate_address(self, rva: int) -> None:
        """Follow the branch/call target of the instruction at ``rva`` (if direct)."""
        line = self._addr_line.get(rva)
        insn = self._line_insn.get(line) if line is not None else None
        if insn is not None and insn.target is not None:
            self.addressActivated.emit(insn.target)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:  # noqa: N802 (Qt override)
        line = self.cursorForPosition(event.position().toPoint()).blockNumber()
        insn = self._line_insn.get(line)
        if insn is not None:
            self.activate_address(insn.address)
        super().mouseDoubleClickEvent(event)
