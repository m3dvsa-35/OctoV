"""Background function discovery so large binaries never freeze the UI."""

from __future__ import annotations

from PySide6.QtCore import QObject, QRunnable, Signal

from octov.core.static.cfg import discover_functions
from octov.core.static.disasm import Disassembler, ImageView
from octov.core.static.pe_parser import PEReport


class DiscoverySignals(QObject):
    finished = Signal(str, object)  # sha256, dict[int, Function]
    failed = Signal(str, str)  # sha256, message


class DiscoveryJob(QRunnable):
    def __init__(self, data: bytes, report: PEReport) -> None:
        super().__init__()
        self.data = data
        self.report = report
        self.signals = DiscoverySignals()

    def run(self) -> None:
        sha = self.report.hashes.sha256
        try:
            dis = Disassembler(ImageView(self.data, self.report))
            functions = discover_functions(dis, self.report)
        except Exception as exc:  # report, never crash the worker thread
            self.signals.failed.emit(sha, str(exc))
            return
        self.signals.finished.emit(sha, functions)
