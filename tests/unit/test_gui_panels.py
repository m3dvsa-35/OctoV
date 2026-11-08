from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication, QGraphicsSimpleTextItem

from octov.core.config import Config
from octov.core.mitre import TECHNIQUES, technique_name
from octov.core.static.cfg import build_function
from octov.core.static.disasm import Disassembler, ImageView
from octov.core.static.pe_parser import parse_pe
from octov.gui.main_window import MainWindow
from octov.gui.widgets.disasm_view import DisassemblyView
from octov.gui.widgets.graph_view import CFGGraphView, EdgeItem
from octov.gui.widgets.hex_view import HexView
from octov.gui.widgets.mitre_view import MitreHeatmap
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

RULES = Path(__file__).resolve().parents[2] / "rules"
BRANCHY = bytes.fromhex("4885C97406B801000000C331C0E80E000000C3") + b"\xcc" * 13 + b"\xc3"
STUB = bytes.fromhex("4C8BD1B8180000000F05")


def _sample() -> bytes:
    return build_pe(
        PESpec(
            sections=[
                SectionSpec(".text", BRANCHY, TEXT),
                SectionSpec(".data", b"\x00" * 32 + STUB, DATA),
            ],
            imports={"kernel32.dll": ["ExitProcess"]},
        )
    )


def _function():  # type: ignore[no-untyped-def]
    data = _sample()
    return build_function(Disassembler(ImageView(data, parse_pe(data))), 0x1000)


# --- MITRE metadata -------------------------------------------------------------


def test_every_catalog_technique_has_a_name() -> None:
    ids = {
        t
        for name in ("evasion_patterns.yaml", "pic_patterns.yaml")
        for rule in yaml.safe_load((RULES / name).read_text(encoding="utf-8"))["rules"]
        for t in rule["mitre"]
    }
    ids |= {"T1027", "T1027.002", "T1027.007", "T1106", "T1055", "T1622", "T1070.006"}
    assert ids <= set(TECHNIQUES)
    assert technique_name("T1055.012") == "Process Hollowing"
    assert technique_name("T9999") == "T9999"


# --- widgets --------------------------------------------------------------------


def test_disassembly_view_lists_blocks_and_navigates(qapp: object) -> None:
    view = DisassemblyView()
    view.set_function(_function())
    text = view.toPlainText()
    assert "loc_1005:" in text and "loc_100b:" in text
    assert "je 0x100b" in text
    hits: list[int] = []
    view.addressActivated.connect(hits.append)
    view.activate_address(0x1003)  # the je instruction
    assert hits == [0x100B]
    view.highlight(0x100B)
    assert view.current_address() == 0x100B


def test_graph_view_draws_blocks_and_labelled_edges(qapp: object) -> None:
    graph = CFGGraphView()
    fn = _function()
    graph.set_function(fn)
    assert set(graph.block_items) == set(fn.blocks)
    edges = [i for i in graph.scene().items() if isinstance(i, EdgeItem)]
    assert sorted(e.kind for e in edges) == ["false", "true"]
    labels = {i.text() for i in graph.scene().items() if isinstance(i, QGraphicsSimpleTextItem)}
    assert {"T", "F"} <= labels
    entry_y = graph.block_items[0x1000].pos().y()
    assert all(entry_y < graph.block_items[b].pos().y() for b in (0x1005, 0x100B))
    graph.highlight(0x1006)  # inside block 0x1005
    assert graph.highlighted_block == 0x1005


def test_hex_view_goto_offset(qapp: object) -> None:
    view = HexView()
    view.set_data(bytes(range(256)) * 8)
    view.goto(0x123)
    line = view.textCursor().block().text()
    assert line.startswith("00000120")
    assert "23" in line.split("  ")[1]


def test_mitre_heatmap_rows_show_text_not_only_colour(qapp: object) -> None:
    heat = MitreHeatmap()
    heat.set_hits(
        [
            ("T1055", "medium", "process_injection_apis"),
            ("T1106", "high", "EVA-001"),
            ("T1106", "high", "EVA-002"),
        ]
    )
    assert heat.rowCount() == 2
    first = [heat.item(0, c).text() for c in range(heat.columnCount())]
    assert first[0] == "T1106" and first[1] == "Native API" and "high" in first
    assert "2" in first


# --- integrated window ------------------------------------------------------------


@pytest.fixture
def window(qapp: object, tmp_path: Path) -> Iterator[MainWindow]:
    settings = QSettings(str(tmp_path / "gui.ini"), QSettings.Format.IniFormat)
    win = MainWindow(Config(), settings=settings)
    yield win
    win.close()


def _wait(predicate, timeout: float = 10.0) -> None:  # type: ignore[no-untyped-def]
    end = time.monotonic() + timeout
    while not predicate():
        QApplication.processEvents()
        assert time.monotonic() < end, "timed out"
        time.sleep(0.01)


def test_window_discovers_functions_in_background(window: MainWindow, tmp_path: Path) -> None:
    path = tmp_path / "s.exe"
    path.write_bytes(_sample())
    assert window.load_sample(path) is not None
    _wait(lambda: window.function_list.count() == 2)
    assert window.graph_view.block_items  # entry function shown


def test_findings_appear_and_navigate_to_evidence(window: MainWindow, tmp_path: Path) -> None:
    path = tmp_path / "s.exe"
    path.write_bytes(_sample())
    report = window.load_sample(path)
    assert report is not None
    _wait(lambda: window.function_list.count() == 2)
    rows = {
        window.indicator_table.item(r, 1).text(): r
        for r in range(window.indicator_table.rowCount())
    }
    assert "EVA-001" in rows
    window.activate_indicator_row(rows["EVA-001"])
    stub_rva = report.sections[1].virtual_address + 32
    assert window.current_rva == stub_rva
    assert (
        window.hex_view.textCursor()
        .block()
        .text()
        .startswith(f"{report.sections[1].raw_offset + 32 & ~0xF:08x}")
    )


def test_navigate_syncs_disassembly_graph_and_hex(window: MainWindow, tmp_path: Path) -> None:
    path = tmp_path / "s.exe"
    path.write_bytes(_sample())
    window.load_sample(path)
    _wait(lambda: window.function_list.count() == 2)
    window.navigate(0x100B)
    assert window.disasm_view.current_address() == 0x100B
    assert window.graph_view.highlighted_block == 0x100B
    assert window.hex_view.textCursor().block().text().startswith("00000400")
