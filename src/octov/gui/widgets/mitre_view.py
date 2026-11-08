"""MITRE ATT&CK technique heat table.

Each row states technique, name, tactic, worst severity (as text), hit count
and sources, so meaning never depends on colour alone; the row tint is an
additional cue.
"""

from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem

from octov.core.mitre import technique_name, technique_tactic
from octov.gui.theme import SEVERITY_COLORS

_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ("Technique", "Name", "Tactic", "Severity", "Hits", "Sources")


class MitreHeatmap(QTableWidget):
    def __init__(self) -> None:
        super().__init__(0, len(COLUMNS))
        self.setHorizontalHeaderLabels(list(COLUMNS))
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(
            len(COLUMNS) - 1, QHeaderView.ResizeMode.Stretch
        )

    def set_hits(self, hits: Iterable[tuple[str, str, str]]) -> None:
        """``hits`` = (technique id, severity, source id) triples."""
        agg: dict[str, dict[str, object]] = {}
        for technique, severity, source in hits:
            entry = agg.setdefault(technique, {"severity": "info", "sources": []})
            if _ORDER.get(severity, 0) > _ORDER.get(str(entry["severity"]), 0):
                entry["severity"] = severity
            sources = entry["sources"]
            assert isinstance(sources, list)
            if source not in sources:
                sources.append(source)

        rows = sorted(
            agg.items(),
            key=lambda kv: (-_ORDER.get(str(kv[1]["severity"]), 0), -len(kv[1]["sources"]), kv[0]),  # type: ignore[arg-type]
        )
        self.setRowCount(len(rows))
        for r, (technique, entry) in enumerate(rows):
            severity = str(entry["severity"])
            sources = entry["sources"]
            assert isinstance(sources, list)
            values = [
                technique,
                technique_name(technique),
                technique_tactic(technique),
                severity,
                str(len(sources)),
                ", ".join(sources),
            ]
            tint = QColor(SEVERITY_COLORS.get(severity, "#888888"))
            tint.setAlpha(32)
            for c, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setBackground(tint)
                self.setItem(r, c, item)
        self.resizeColumnsToContents()
