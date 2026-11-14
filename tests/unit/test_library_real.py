"""Library recognition with the real FLARE signature files (skipped when not installed)."""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

from octov.core.analysis.library import LibraryMatch, accept
from octov.core.static.cfg import discover_functions
from octov.core.static.disasm import Disassembler, ImageView
from octov.core.static.pe_parser import parse_pe
from octov.ext import DEFAULT_SIGS_ROOT
from octov.ext.library import library_command, library_sigs_dir, parse_library
from octov.ext.runner import parse_json, run_engine

SIGS = library_sigs_dir(DEFAULT_SIGS_ROOT.expanduser())
# pip ships launchers that are statically linked against the MSVC runtime
STATIC_CRT = Path(sys.prefix) / "Lib" / "site-packages" / "pip" / "_vendor" / "distlib" / "t64.exe"
NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")

pytestmark = pytest.mark.skipif(
    SIGS is None or not any(SIGS[1].glob("*.sig")), reason="FLARE signature files not installed"
)


def _recognise(sample: Path, tmp_path: Path) -> tuple[dict[int, LibraryMatch], int]:
    assert SIGS is not None
    data = sample.read_bytes()
    report = parse_pe(data)
    functions = discover_functions(Disassembler(ImageView(data, report)), report)
    starts = tmp_path / "starts.json"
    starts.write_text(json.dumps(sorted(functions)), encoding="utf-8")
    run = run_engine(
        library_command(sample, SIGS[1], starts),
        timeout_s=120,
        max_memory_mb=2048,
        cancel=threading.Event(),
    )
    sizes = {start: fn.size for start, fn in functions.items()}
    return accept(parse_library(parse_json(run)), sizes), len(functions)


@pytest.mark.skipif(not STATIC_CRT.is_file(), reason="pip's t64.exe launcher not present")
def test_statically_linked_runtime_is_recognised(tmp_path: Path) -> None:
    matches, total = _recognise(STATIC_CRT, tmp_path)
    assert len(matches) >= 150, (len(matches), total)
    names = {m.name for m in matches.values()}
    assert {"free", "_errno", "_lock"} <= names


@pytest.mark.skipif(not NOTEPAD.is_file(), reason="notepad.exe not present")
def test_a_lone_look_alike_from_another_library_is_not_named(tmp_path: Path) -> None:
    matches, _total = _recognise(NOTEPAD, tmp_path)
    assert not [m for m in matches.values() if "atlmfc" in m.source], matches
    assert not [m for m in matches.values() if "CMFC" in m.name]


CURL = Path(r"C:\Windows\System32\curl.exe")


@pytest.mark.skipif(not CURL.is_file(), reason="curl.exe not present")
def test_scattered_look_alikes_are_not_named(tmp_path: Path) -> None:
    # before the neighbour rule curl.exe got 10 MFC names and several Crypto++ names
    matches, _total = _recognise(CURL, tmp_path)
    assert len(matches) >= 20  # the statically linked MSVC startup code is still recognised
    assert {m.source for m in matches.values()} == {"1_flare_msvc_rtf_32_64.sig"}
    assert not [m.name for m in matches.values() if "CryptoPP" in m.name or "CMFC" in m.name]
