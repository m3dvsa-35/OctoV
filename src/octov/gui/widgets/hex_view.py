"""Windowed hex dump (renders only the region around the current offset)."""

from __future__ import annotations

from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import QPlainTextEdit

BYTES_PER_LINE = 16
WINDOW_LINES = 256


class HexView(QPlainTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._data = b""
        self._window_start = 0

    def set_data(self, data: bytes) -> None:
        self._data = data
        self.goto(0)

    def _render(self, start: int) -> None:
        lines = []
        end = min(len(self._data), start + WINDOW_LINES * BYTES_PER_LINE)
        for off in range(start, end, BYTES_PER_LINE):
            chunk = self._data[off : off + BYTES_PER_LINE]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            lines.append(f"{off:08x}  {hex_part:<47}  {text}")
        self.setPlainText("\n".join(lines))
        self._window_start = start

    def goto(self, offset: int) -> None:
        if not self._data:
            self.clear()
            return
        offset = max(0, min(offset, len(self._data) - 1))
        line_start = offset - offset % BYTES_PER_LINE
        window = max(0, line_start - (WINDOW_LINES // 4) * BYTES_PER_LINE)
        self._render(window)
        block = self.document().findBlockByNumber((line_start - window) // BYTES_PER_LINE)
        cursor = QTextCursor(block)
        self.setTextCursor(cursor)
        self.centerCursor()
