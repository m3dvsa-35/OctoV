from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDockWidget

from octov.core.config import Config
from octov.core.session.session import Session
from octov.gui.main_window import DOCK_IDS, MainWindow
from tests.samples.builder import PESpec, build_pe


@pytest.fixture
def window(qapp: object, tmp_path: Path) -> Iterator[MainWindow]:
    settings = QSettings(str(tmp_path / "gui.ini"), QSettings.Format.IniFormat)
    win = MainWindow(Config(), settings=settings)
    yield win
    win.close()


def _injector(tmp_path: Path) -> Path:
    path = tmp_path / "inj.exe"
    path.write_bytes(
        build_pe(PESpec(imports={"kernel32.dll": ["WriteProcessMemory", "CreateRemoteThread"]}))
    )
    return path


def test_creates_all_dock_panels(window: MainWindow) -> None:
    names = {d.objectName() for d in window.findChildren(QDockWidget)}
    assert names == {f"dock_{i}" for i in DOCK_IDS}
    assert {
        "samples",
        "overview",
        "indicators",
        "disassembly",
        "pseudocode",
        "graph",
        "memory_map",
        "ai_chat",
    } <= set(DOCK_IDS)


def test_switching_language_retranslates_ui(window: MainWindow) -> None:
    window.set_language("az")
    assert window.windowTitle() == "OctoV - Binar Analiz İş Masası"
    assert window.dock("samples").windowTitle() == "Nümunələr"
    assert window.menu_file.title() == "Fayl"
    window.set_language("en")
    assert window.dock("samples").windowTitle() == "Samples"


def test_switching_theme_changes_stylesheet(window: MainWindow) -> None:
    window.set_theme("light")
    light = window.styleSheet()
    window.set_theme("dark")
    assert window.current_theme == "dark"
    assert window.styleSheet() != light


def test_load_sample_populates_panels(window: MainWindow, tmp_path: Path) -> None:
    report = window.load_sample(_injector(tmp_path))
    assert report is not None
    assert report.hashes.sha256 in window.overview_text.toPlainText()
    ids = [
        window.indicator_table.item(r, 1).text() for r in range(window.indicator_table.rowCount())
    ]
    assert "process_injection_apis" in ids
    assert window.sample_list.count() == 1
    assert "inj.exe" in window.statusBar().currentMessage()


def test_load_invalid_sample_reports_error_without_raising(
    window: MainWindow, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"not a pe")
    assert window.load_sample(bad) is None
    assert "Error" in window.statusBar().currentMessage()
    assert window.sample_list.count() == 0


def test_loaded_sample_is_saved_to_attached_session(window: MainWindow, tmp_path: Path) -> None:
    session = Session.create(tmp_path / "case.octov")
    window.attach_session(session)
    report = window.load_sample(_injector(tmp_path))
    assert report is not None
    assert session.get_sample(report.hashes.sha256) is not None
    window.attach_session(None)
