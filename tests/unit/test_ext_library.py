from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from octov.core.analysis.library import Candidate
from octov.core.static.cfg import discover_functions
from octov.core.static.disasm import Disassembler, ImageView
from octov.core.static.pe_parser import parse_pe
from octov.ext.library import (
    WORKER_VERSION,
    library_command,
    library_sigs_dir,
    library_status,
    parse_library,
)
from octov.ext.library_worker import match_file
from octov.ext.runner import EngineError, parse_json, run_engine
from tests.samples.builder import library_like_pe


def write_pat(sigs_dir: Path, data: bytes, starts: list[int], name: str = "test.pat") -> None:
    """A FLIRT .pat file naming the functions at ``starts`` as ``lib_<rva>``."""
    view = ImageView(data, parse_pe(data))
    lines = [
        f"{view.read(s, 32).hex().upper()} 00 0000 0029 :0000 lib_{s:x}" for s in sorted(starts)
    ]
    sigs_dir.mkdir(parents=True, exist_ok=True)
    (sigs_dir / name).write_bytes(("\n".join(lines) + "\n---\n").encode("ascii"))


def library_sample(tmp_path: Path) -> tuple[Path, Path, list[int]]:
    """(sample path, signature root, starts of the 7 library-like functions)."""
    data = library_like_pe()
    report = parse_pe(data)
    functions = discover_functions(Disassembler(ImageView(data, report)), report)
    starts = sorted(s for s in functions if s != report.entry_point)
    assert len(starts) == 7
    sample = tmp_path / "lib.exe"
    sample.write_bytes(data)
    root = tmp_path / "sigs"
    write_pat(root / "v1.0.0", data, starts)
    return sample, root, starts


def _expected(starts: list[int]) -> list[Candidate]:
    return [Candidate(s, "test.pat", (f"lib_{s:x}",), 1) for s in starts]


def test_worker_names_the_functions_it_has_signatures_for(tmp_path: Path) -> None:
    sample, root, starts = library_sample(tmp_path)
    entry = parse_pe(sample).entry_point
    doc = match_file(sample, root / "v1.0.0", [entry, *starts])
    assert doc["sets"] == [{"file": "test.pat", "signatures": 7}]
    assert parse_library(doc) == _expected(starts)  # the entry function has no name


def test_worker_skips_starts_it_cannot_read(tmp_path: Path) -> None:
    sample, root, starts = library_sample(tmp_path)
    doc = match_file(sample, root / "v1.0.0", [0x7FFFFFFF, 0, -5, starts[0]])
    assert parse_library(doc) == _expected(starts[:1])


def test_worker_reports_every_name_of_an_ambiguous_function(tmp_path: Path) -> None:
    sample, root, starts = library_sample(tmp_path)
    data = sample.read_bytes()
    sigs = root / "v1.0.0"
    line = (sigs / "test.pat").read_bytes().decode().splitlines()[0]
    twin = line.rsplit(" ", 1)[0] + " other_name"
    (sigs / "test.pat").write_bytes(f"{line}\n{twin}\n---\n".encode("ascii"))
    (got,) = parse_library(match_file(sample, sigs, starts))
    assert got == Candidate(starts[0], "test.pat", (f"lib_{starts[0]:x}", "other_name"), 2)
    assert data == sample.read_bytes()


def test_worker_runs_as_a_child_process(tmp_path: Path) -> None:
    sample, root, starts = library_sample(tmp_path)
    starts_file = tmp_path / "starts.json"
    starts_file.write_text(str(starts), encoding="utf-8")
    run = run_engine(
        library_command(sample, root / "v1.0.0", starts_file),
        timeout_s=60,
        max_memory_mb=1024,
        cancel=threading.Event(),
    )
    assert parse_library(parse_json(run)) == _expected(starts)


@pytest.mark.parametrize(
    "doc",
    [
        {"ok": True},
        {"engine": "library", "version": 2, "sets": [], "candidates": []},
        {"engine": "library", "version": 1, "sets": [], "candidates": [{"set": "a", "names": []}]},
        {"engine": "library", "version": 1, "sets": [], "candidates": "x"},
        {
            "engine": "library",
            "version": 1,
            "sets": [],
            "candidates": [{"rva": "1", "set": "a", "names": ["n"], "count": 1}],
        },
    ],
)
def test_parse_library_rejects_foreign_documents(doc: dict[str, Any]) -> None:
    with pytest.raises(EngineError) as err:
        parse_library(doc)
    assert err.value.kind == "bad_output"


def test_status_needs_signatures(tmp_path: Path) -> None:
    empty = library_status(tmp_path / "none")
    assert (empty.id, empty.ready, empty.reason_key) == (
        "library",
        False,
        "ext.reason.no_signatures",
    )
    assert empty.setup_cmd == "octov ext setup library"

    _sample, root, _starts = library_sample(tmp_path)
    missing = library_status(root, finder=lambda name: None)
    assert (missing.installed, missing.ready, missing.reason_key) == (
        False,
        False,
        "ext.reason.not_installed",
    )

    ready = library_status(root)
    assert ready.ready and ready.reason_key is None
    assert (ready.version, ready.rules_version) == (WORKER_VERSION, "v1.0.0")


def test_newest_signature_folder_wins(tmp_path: Path) -> None:
    for name in ("v1.0.0", "v10.0.0", "v9.2.0", "junk"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "x.sig").write_bytes(b"")
    (tmp_path / "v11.0.0").mkdir()  # no signature file inside
    assert library_sigs_dir(tmp_path) == ("v10.0.0", tmp_path / "v10.0.0")


def test_worker_ignores_bytes_the_file_does_not_have(tmp_path: Path) -> None:
    # An executable section without raw data (UPX0-like) reads as zero padding, not code:
    # a signature that zeros satisfy must not name "functions" there.
    from tests.samples.builder import TEXT, PESpec, SectionSpec, build_pe

    data = build_pe(
        PESpec(
            sections=[
                SectionSpec(".text", b"\xc3" + b"\x90" * 15, TEXT),
                SectionSpec("UPX0", b"", TEXT, virtual_size=0x1000),
            ]
        )
    )
    report = parse_pe(data)
    empty = next(s for s in report.sections if s.name.startswith("UPX0"))
    assert empty.raw_size == 0 and empty.executable
    sample = tmp_path / "packed.exe"
    sample.write_bytes(data)
    sigs = tmp_path / "sigs" / "v1.0.0"
    sigs.mkdir(parents=True)
    (sigs / "zero.pat").write_bytes(("00" * 32 + " 00 0000 0020 :0000 zero_fn\n---\n").encode())
    starts = [empty.virtual_address, empty.virtual_address + 0x100]
    assert parse_library(match_file(sample, sigs, starts)) == []
