"""OctoV main window: a dockable, themeable, translatable workbench shell.

M1 wires static PE triage (overview + indicators) and session persistence;
other panels are placeholders filled in later milestones.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QByteArray, QSettings, Qt
from PySide6.QtGui import QAction, QActionGroup, QCloseEvent, QColor, QShowEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDockWidget,
    QFileDialog,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

from octov import __version__
from octov.core.config import Config
from octov.core.i18n import LANGUAGES, tr
from octov.core.session.session import Session, SessionError
from octov.core.static.pe_parser import PEParseError, PEReport, parse_pe
from octov.gui.theme import SEVERITY_COLORS, stylesheet


@dataclass(frozen=True)
class _DockSpec:
    id: str
    area: Qt.DockWidgetArea
    milestone: str | None = None  # None = implemented


_TOP = Qt.DockWidgetArea.TopDockWidgetArea
_LEFT = Qt.DockWidgetArea.LeftDockWidgetArea
_RIGHT = Qt.DockWidgetArea.RightDockWidgetArea
_BOTTOM = Qt.DockWidgetArea.BottomDockWidgetArea

_DOCKS: tuple[_DockSpec, ...] = (
    _DockSpec("samples", _LEFT),
    _DockSpec("overview", _TOP),
    _DockSpec("disassembly", _TOP, "M2"),
    _DockSpec("pseudocode", _TOP, "M2"),
    _DockSpec("graph", _TOP, "M2"),
    _DockSpec("hex", _TOP, "M2"),
    _DockSpec("indicators", _BOTTOM),
    _DockSpec("mitre", _BOTTOM, "M2"),
    _DockSpec("memory_map", _BOTTOM, "M3"),
    _DockSpec("timeline", _BOTTOM, "M3"),
    _DockSpec("log", _BOTTOM),
    _DockSpec("ai_chat", _RIGHT, "M5"),
)
DOCK_IDS: tuple[str, ...] = tuple(d.id for d in _DOCKS)

_INDICATOR_COLUMNS = ("severity", "id", "mitre", "description")
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class MainWindow(QMainWindow):
    def __init__(self, config: Config | None = None, settings: QSettings | None = None) -> None:
        super().__init__()
        self.config = config or Config()
        self.settings = settings or QSettings("OctoV", "OctoV")
        self.language = str(self.settings.value("ui/language", self.config.ui.language))
        if self.language not in LANGUAGES:
            self.language = self.config.ui.language
        self.current_theme = str(self.settings.value("ui/theme", self.config.ui.theme))
        self.session: Session | None = None
        self._reports: dict[str, PEReport] = {}
        self._docks: dict[str, QDockWidget] = {}
        self._placeholders: dict[str, QLabel] = {}
        self._actions: dict[str, QAction] = {}

        self.setDockNestingEnabled(True)
        # Side panels (samples, AI chat) take full height; top/bottom sit between them.
        self.setCorner(Qt.Corner.TopLeftCorner, _LEFT)
        self.setCorner(Qt.Corner.BottomLeftCorner, _LEFT)
        self.setCorner(Qt.Corner.TopRightCorner, _RIGHT)
        self.setCorner(Qt.Corner.BottomRightCorner, _RIGHT)
        self.resize(1440, 900)
        self._build_panels()
        self._build_menus()
        self._default_state: QByteArray | None = None
        self._layout_restored = self._restore_layout()
        self.set_theme(self.current_theme)
        self.retranslate()
        self.statusBar().showMessage(self._tr("status.ready"))

    # -- construction ----------------------------------------------------

    def _tr(self, key: str, **kwargs: object) -> str:
        return tr(key, self.language, **kwargs)

    def _build_panels(self) -> None:
        self.sample_list = QListWidget()
        self.sample_list.currentItemChanged.connect(self._on_sample_selected)

        self.overview_text = QPlainTextEdit()
        self.overview_text.setReadOnly(True)
        self.overview_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        self.indicator_table = QTableWidget(0, len(_INDICATOR_COLUMNS))
        self.indicator_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.indicator_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.indicator_table.verticalHeader().setVisible(False)
        self.indicator_table.horizontalHeader().setSectionResizeMode(
            len(_INDICATOR_COLUMNS) - 1, QHeaderView.ResizeMode.Stretch
        )

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)

        widgets: dict[str, QWidget] = {
            "samples": self.sample_list,
            "overview": self.overview_text,
            "indicators": self.indicator_table,
            "log": self.log_view,
        }
        first_in_area: dict[Qt.DockWidgetArea, QDockWidget] = {}
        for spec in _DOCKS:
            dock = QDockWidget(self)
            dock.setObjectName(f"dock_{spec.id}")
            widget = widgets.get(spec.id)
            if widget is None:
                label = QLabel()
                label.setObjectName("placeholder")
                label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                label.setWordWrap(True)
                self._placeholders[spec.id] = label
                widget = label
            dock.setWidget(widget)
            self.addDockWidget(spec.area, dock)
            if spec.area in first_in_area:
                self.tabifyDockWidget(first_in_area[spec.area], dock)
            else:
                first_in_area[spec.area] = dock
            self._docks[spec.id] = dock
        for dock in first_in_area.values():
            dock.raise_()

    def _apply_default_sizes(self) -> None:
        self.resizeDocks(
            [self._docks[d] for d in ("samples", "overview", "ai_chat")],
            [240, max(400, self.width() - 600), 340],
            Qt.Orientation.Horizontal,
        )
        self.resizeDocks(
            [self._docks["overview"], self._docks["indicators"]],
            [560, 300],
            Qt.Orientation.Vertical,
        )

    def _action(self, key: str, slot: object, shortcut: str | None = None) -> QAction:
        action = QAction(self)
        if shortcut:
            action.setShortcut(shortcut)
        action.triggered.connect(slot)
        self._actions[key] = action
        return action

    def _build_menus(self) -> None:
        bar = self.menuBar()
        self.menu_file = QMenu(self)
        self.menu_file.addAction(
            self._action("action.open_sample", self._open_sample_dialog, "Ctrl+O")
        )
        self.menu_file.addSeparator()
        self.menu_file.addAction(
            self._action("action.new_session", self._new_session_dialog, "Ctrl+N")
        )
        self.menu_file.addAction(self._action("action.open_session", self._open_session_dialog))
        self.menu_file.addSeparator()
        self.menu_file.addAction(self._action("action.exit", self.close, "Ctrl+Q"))

        self.menu_view = QMenu(self)
        theme_group = QActionGroup(self)
        for theme in ("dark", "light"):
            act = self._action(f"action.theme_{theme}", lambda _=False, t=theme: self.set_theme(t))
            act.setCheckable(True)
            act.setChecked(theme == self.current_theme)
            theme_group.addAction(act)
            self.menu_view.addAction(act)
        self.menu_view.addSeparator()
        self.menu_language = QMenu(self)
        lang_group = QActionGroup(self)
        for code, name in (("en", "English"), ("az", "Azərbaycan")):
            act = QAction(name, self, checkable=True)
            act.setChecked(code == self.language)
            act.triggered.connect(lambda _=False, c=code: self.set_language(c))
            lang_group.addAction(act)
            self.menu_language.addAction(act)
        self.menu_view.addMenu(self.menu_language)
        self.menu_view.addSeparator()
        for dock in self._docks.values():
            self.menu_view.addAction(dock.toggleViewAction())
        self.menu_view.addSeparator()
        self.menu_view.addAction(self._action("action.reset_layout", self.reset_layout))

        self.menu_help = QMenu(self)
        self.menu_help.addAction(self._action("action.about", self._show_about))

        for menu in (self.menu_file, self.menu_view, self.menu_help):
            bar.addMenu(menu)

    # -- public API --------------------------------------------------------

    def dock(self, dock_id: str) -> QDockWidget:
        return self._docks[dock_id]

    def set_language(self, lang: str) -> None:
        if lang not in LANGUAGES:
            raise ValueError(f"unsupported language: {lang}")
        self.language = lang
        self.settings.setValue("ui/language", lang)
        self.retranslate()

    def set_theme(self, theme: str) -> None:
        self.current_theme = theme
        self.settings.setValue("ui/theme", theme)
        self.setStyleSheet(stylesheet(theme))
        action = self._actions.get(f"action.theme_{theme}")
        if action:
            action.setChecked(True)

    def retranslate(self) -> None:
        self.setWindowTitle(self._tr("app.title"))
        self.menu_file.setTitle(self._tr("menu.file"))
        self.menu_view.setTitle(self._tr("menu.view"))
        self.menu_language.setTitle(self._tr("menu.language"))
        self.menu_help.setTitle(self._tr("menu.help"))
        for key, action in self._actions.items():
            action.setText(self._tr(key))
        for spec in _DOCKS:
            title = self._tr(f"dock.{spec.id}")
            self._docks[spec.id].setWindowTitle(title)
            if spec.milestone and spec.id in self._placeholders:
                self._placeholders[spec.id].setText(
                    self._tr("placeholder.milestone", panel=title, milestone=spec.milestone)
                )
        self.indicator_table.setHorizontalHeaderLabels(
            [self._tr(f"indicators.column.{c}") for c in _INDICATOR_COLUMNS]
        )
        if not self._reports:
            self.overview_text.setPlainText(self._tr("overview.empty"))

    def reset_layout(self) -> None:
        if self._default_state is not None:
            self.restoreState(self._default_state)
        else:
            self._apply_default_sizes()

    def attach_session(self, session: Session | None) -> None:
        if self.session is not None and self.session is not session:
            self.session.commit()
            self.session.close()
        self.session = session
        if session is not None:
            self.sample_list.clear()
            self._reports.clear()
            for row in session.list_samples():
                data = session.get_sample(row.sha256)
                if data is not None:
                    self._add_sample_item(Path(row.path or row.sha256).name, row.sha256)
            self._log(f"session: {session.path}")

    def load_sample(self, path: str | Path) -> PEReport | None:
        """Statically triage ``path``; populate the UI. Returns ``None`` on failure."""
        path = Path(path)
        try:
            size = path.stat().st_size
            if size > self.config.static.max_file_size_mb * 1024 * 1024:
                raise PEParseError(f"file exceeds {self.config.static.max_file_size_mb} MB limit")
            report = parse_pe(path)
            if self.session is not None:
                self.session.add_sample(report)
                self.session.commit()
        except (OSError, PEParseError, SessionError) as exc:
            message = self._tr("status.error", message=str(exc))
            self.statusBar().showMessage(message)
            self._log(message)
            return None

        sha = report.hashes.sha256
        self._reports[sha] = report
        existing = self._find_sample_item(sha)
        if existing is None:
            self._add_sample_item(path.name, sha)
        else:
            self.sample_list.setCurrentItem(existing)
        self._show_report(report)
        message = self._tr("status.loaded", name=path.name)
        self.statusBar().showMessage(message)
        self._log(f"{message} sha256={sha} indicators={len(report.indicators)}")
        return report

    # -- internals ---------------------------------------------------------

    def _log(self, text: str) -> None:
        self.log_view.appendPlainText(text)

    def _find_sample_item(self, sha: str) -> QListWidgetItem | None:
        for i in range(self.sample_list.count()):
            item = self.sample_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == sha:
                return item
        return None

    def _add_sample_item(self, name: str, sha: str) -> None:
        item = QListWidgetItem(name)
        item.setData(Qt.ItemDataRole.UserRole, sha)
        item.setToolTip(sha)
        self.sample_list.addItem(item)
        self.sample_list.setCurrentItem(item)

    def _on_sample_selected(self, current: QListWidgetItem | None, _prev: object) -> None:
        if current is None:
            return
        sha = current.data(Qt.ItemDataRole.UserRole)
        report = self._reports.get(sha)
        if report is None and self.session is not None:
            data = self.session.get_sample(sha)
            if data is not None:
                self.overview_text.setPlainText(_format_dict_overview(data))
                self._fill_indicators(data.get("indicators", []))
            return
        if report is not None:
            self._show_report(report)

    def _show_report(self, r: PEReport) -> None:
        self.overview_text.setPlainText(_format_overview(r))
        self._fill_indicators(
            [
                {"severity": i.severity, "id": i.id, "mitre": i.mitre, "description": i.description}
                for i in r.indicators
            ]
        )

    def _fill_indicators(self, indicators: list[dict[str, object]]) -> None:
        rows = sorted(indicators, key=lambda i: _SEVERITY_ORDER.get(str(i["severity"]), 9))
        self.indicator_table.setRowCount(len(rows))
        for row, ind in enumerate(rows):
            mitre = ind.get("mitre") or []
            values = [
                str(ind["severity"]),
                str(ind["id"]),
                ", ".join(str(m) for m in mitre) if isinstance(mitre, list) else str(mitre),
                str(ind["description"]),
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 0:
                    item.setForeground(QColor(SEVERITY_COLORS.get(value, "#888888")))
                self.indicator_table.setItem(row, col, item)
        self.indicator_table.resizeColumnsToContents()

    def _open_sample_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, self._tr("dialog.open_sample"), "", "PE (*.exe *.dll *.sys *.bin);;* (*)"
        )
        if path:
            self.load_sample(path)

    def _new_session_dialog(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, self._tr("action.new_session"), "", self._tr("dialog.session_filter")
        )
        if path:
            try:
                self.attach_session(Session.create(path))
            except SessionError as exc:
                self.statusBar().showMessage(self._tr("status.error", message=str(exc)))

    def _open_session_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, self._tr("action.open_session"), "", self._tr("dialog.session_filter")
        )
        if path:
            try:
                self.attach_session(Session.open(path))
            except SessionError as exc:
                self.statusBar().showMessage(self._tr("status.error", message=str(exc)))

    def _show_about(self) -> None:
        QMessageBox.about(
            self, self._tr("action.about"), self._tr("about.text", version=__version__)
        )

    def _restore_layout(self) -> bool:
        geometry = self.settings.value("window/geometry")
        state = self.settings.value("window/state")
        if isinstance(geometry, QByteArray):
            self.restoreGeometry(geometry)
        return isinstance(state, QByteArray) and self.restoreState(state)

    def showEvent(self, event: QShowEvent) -> None:  # noqa: N802 (Qt override)
        super().showEvent(event)
        if self._default_state is None:
            # Dock sizes only take effect once the window has real geometry.
            saved = self.saveState() if self._layout_restored else None
            self._apply_default_sizes()
            self._default_state = self.saveState()
            if saved is not None:
                self.restoreState(saved)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 (Qt override)
        self.settings.setValue("window/geometry", self.saveGeometry())
        self.settings.setValue("window/state", self.saveState())
        self.settings.sync()
        if self.session is not None:
            self.session.commit()
        super().closeEvent(event)


def _format_overview(r: PEReport) -> str:
    lines = [
        f"File        : {r.path or '<memory>'}",
        f"Size        : {r.size:,} bytes",
        f"SHA-256     : {r.hashes.sha256}",
        f"SHA-1       : {r.hashes.sha1}",
        f"MD5         : {r.hashes.md5}",
        f"Imphash     : {r.hashes.imphash or '-'}",
        f"Machine     : {r.machine} ({'PE32+' if r.is_64bit else 'PE32'}, "
        f"{'DLL' if r.is_dll else 'EXE'}, {r.subsystem})",
        f"Compiled    : {r.compile_time.isoformat()}",
        f"Entry point : {r.entry_point:#x}  (image base {r.image_base:#x})",
        f"Entropy     : {r.entropy:.3f}",
        f"Signature   : {'present' if r.signature.present else 'none'}",
        f"Overlay     : {r.overlay_size:,} bytes",
        "",
        "Sections:",
        f"  {'name':<10}{'VA':>10}{'VSize':>10}{'RawSize':>10}{'Entropy':>9}  Perm",
    ]
    for s in r.sections:
        perm = (
            ("R" if s.readable else "-")
            + ("W" if s.writable else "-")
            + ("X" if s.executable else "-")
        )
        lines.append(
            f"  {s.name:<10}{s.virtual_address:>#10x}{s.virtual_size:>#10x}"
            f"{s.raw_size:>#10x}{s.entropy:>9.3f}  {perm}"
        )
    lines += ["", f"Imports ({r.import_count}):"]
    for dll, funcs in r.imports.items():
        lines.append(f"  {dll}: {', '.join(funcs)}")
    if r.exports:
        lines += ["", f"Exports ({len(r.exports)}): {', '.join(r.exports[:50])}"]
    return "\n".join(lines)


def _format_dict_overview(data: dict[str, object]) -> str:
    hashes = data.get("hashes")
    sha = hashes.get("sha256") if isinstance(hashes, dict) else "?"
    return f"File    : {data.get('path')}\nSize    : {data.get('size')}\nSHA-256 : {sha}\n"
