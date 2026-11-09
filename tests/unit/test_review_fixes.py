"""Regression tests for the M2 code-review findings."""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication

from octov.cli.main import main
from octov.core.config import Config
from octov.core.session.session import Session
from octov.core.static.analysis import analyze
from octov.core.static.disasm import Disassembler, ImageView
from octov.core.static.pe_parser import parse_pe
from octov.gui.main_window import MAX_LOADED_SAMPLES, MainWindow
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

BRANCHY = bytes.fromhex("4885C97406B801000000C331C0E80E000000C3") + b"\xcc" * 13 + b"\xc3"
STUB = bytes.fromhex("4C8BD1B8180000000F05")


def _sample(tag: bytes = b"") -> bytes:
    return build_pe(
        PESpec(
            sections=[
                SectionSpec(".text", BRANCHY, TEXT),
                SectionSpec(".data", b"\x00" * 32 + STUB + b"\x00" * 8 + tag, DATA),
            ],
            imports={"kernel32.dll": ["ExitProcess"]},
        )
    )


def _wait(predicate, timeout: float = 10.0) -> None:  # type: ignore[no-untyped-def]
    end = time.monotonic() + timeout
    while not predicate():
        QApplication.processEvents()
        assert time.monotonic() < end, "timed out"
        time.sleep(0.01)


def _custom_rules(tmp_path: Path) -> Path:
    path = tmp_path / "custom.yaml"
    rule = {
        "id": "CUST-1",
        "name": "custom marker",
        "description": "test marker string",
        "severity": "low",
        "mitre": ["T1027"],
        "condition": "any",
        "indicators": [{"type": "string", "value": "octov-test-marker"}],
    }
    path.write_text(yaml.safe_dump({"version": 1, "rules": [rule]}), encoding="utf-8")
    return path


def _window(tmp_path: Path, config: Config | None = None) -> MainWindow:
    settings = QSettings(str(tmp_path / "gui.ini"), QSettings.Format.IniFormat)
    return MainWindow(config or Config(), settings=settings)


@pytest.fixture
def window(qapp: object, tmp_path: Path) -> Iterator[MainWindow]:
    win = _window(tmp_path)
    yield win
    win.close()


def _row_of(win: MainWindow, ident: str) -> int:
    for r in range(win.indicator_table.rowCount()):
        if win.indicator_table.item(r, 1).text() == ident:
            return r
    raise AssertionError(f"{ident} not in indicator table")


# --- finding 1: session-only samples must not navigate inside another sample ----


def test_session_sample_rows_do_not_navigate_other_sample(
    window: MainWindow, tmp_path: Path
) -> None:
    a = tmp_path / "a.exe"
    a.write_bytes(_sample(b"A"))
    window.load_sample(a)
    _wait(lambda: window.function_list.count() == 2)

    session = Session.create(tmp_path / "case.octov")
    session.add_sample(analyze(_sample(b"B")))
    window.attach_session(session)
    window.current_rva = None
    window.activate_indicator_row(_row_of(window, "EVA-001"))
    assert window.current_rva is None
    assert window.disasm_view.toPlainText() == ""
    window.attach_session(None)


# --- finding 2: switching samples clears code views until discovery is done -----


def test_loading_another_sample_clears_stale_code_views(window: MainWindow, tmp_path: Path) -> None:
    a, b = tmp_path / "a.exe", tmp_path / "b.exe"
    a.write_bytes(_sample(b"A"))
    b.write_bytes(_sample(b"B"))
    window.load_sample(a)
    _wait(lambda: window.function_list.count() == 2)
    assert window.graph_view.block_items
    window.load_sample(b)
    assert window.graph_view.block_items == {}
    assert window.graph_view.function is None
    assert window.disasm_view.toPlainText() == ""


# --- finding 3: configured rule paths are honoured ---------------------------------


def test_gui_uses_configured_rule_paths(qapp: object, tmp_path: Path) -> None:
    cfg = Config()
    cfg.rules.paths = [*cfg.rules.paths, _custom_rules(tmp_path)]
    win = _window(tmp_path, cfg)
    try:
        path = tmp_path / "m.exe"
        path.write_bytes(_sample(b"octov-test-marker"))
        win.load_sample(path)
        _row_of(win, "CUST-1")
        _row_of(win, "EVA-001")
    finally:
        win.close()


def test_cli_uses_rule_paths_from_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    custom = _custom_rules(tmp_path)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"rules:\n  paths: [{custom.name}]\n", encoding="utf-8")
    sample = tmp_path / "m.exe"
    sample.write_bytes(_sample(b"octov-test-marker"))
    assert main(["analyze", str(sample), "--config", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert "CUST-1" in out
    assert "EVA-001" not in out  # catalog list replaced by config


# --- finding 5: --rules cannot silently duplicate shipped rule ids -----------------


def test_cli_rejects_duplicate_rule_ids(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dup = tmp_path / "dup.yaml"
    rule = {
        "id": "EVA-001",
        "name": "dup",
        "description": "d",
        "severity": "low",
        "mitre": ["T1106"],
        "indicators": [{"type": "string", "value": "x"}],
    }
    dup.write_text(yaml.safe_dump({"version": 1, "rules": [rule]}), encoding="utf-8")
    sample = tmp_path / "m.exe"
    sample.write_bytes(_sample())
    assert main(["analyze", str(sample), "--rules", str(dup)]) == 2
    assert "duplicate" in capsys.readouterr().err


# --- findings 4 & 6: far branches and decimal targets -------------------------------


def _dis() -> Disassembler:
    data = _sample()
    return Disassembler(ImageView(data, parse_pe(data)))


def test_far_jump_and_call_are_branches() -> None:
    dis = _dis()
    ljmp = dis._convert(0x1000, 7, "ljmp", "0x33:0x1010", b"")
    lcall = dis._convert(0x1000, 7, "lcall", "0x33:0x1010", b"")
    assert ljmp.is_jump and not ljmp.is_conditional and ljmp.target is None
    assert lcall.is_call


def test_decimal_branch_targets_are_parsed() -> None:
    dis = _dis()
    assert dis._convert(0, 2, "jmp", "5", b"").target == 5
    assert dis._convert(0, 2, "jmp", "rax", b"").target is None


# --- finding 7: new UI text is translated -------------------------------------------


def test_new_panels_are_translated(window: MainWindow) -> None:
    window.set_language("az")
    headers = [
        window.mitre_view.horizontalHeaderItem(c).text()
        for c in range(window.mitre_view.columnCount())
    ]
    assert headers[0] == "Texnika"
    window.set_language("en")
    assert window.mitre_view.horizontalHeaderItem(0).text() == "Technique"


# --- finding 9: loaded samples are bounded ------------------------------------------


def test_loaded_sample_cache_is_bounded_and_reloads(window: MainWindow, tmp_path: Path) -> None:
    paths = []
    for i in range(MAX_LOADED_SAMPLES + 2):
        p = tmp_path / f"s{i}.exe"
        p.write_bytes(_sample(f"tag{i}".encode()))
        paths.append(p)
        window.load_sample(p)
    assert len(window._data) <= MAX_LOADED_SAMPLES
    first = window.sample_list.item(0)
    window.sample_list.setCurrentItem(first)
    sha = first.data(Qt.ItemDataRole.UserRole)
    assert window._current_sha == sha
    assert sha in window._data
