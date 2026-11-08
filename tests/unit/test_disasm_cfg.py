from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

from octov.core.static.cfg import build_function, discover_functions
from octov.core.static.disasm import Disassembler, ImageView
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import TEXT, PESpec, SectionSpec, build_pe

TEXT_RVA = 0x1000

# test rcx,rcx; je L1; mov eax,1; ret; L1: xor eax,eax; call helper; ret; int3 pad; helper: ret
BRANCHY = bytes.fromhex("4885C97406B801000000C331C0E80E000000C3") + b"\xcc" * 13 + b"\xc3"
# xor eax,eax / L: inc eax / cmp eax,10 / jne L / ret
LOOP = bytes.fromhex("31C0FFC083F80A75F9C3")


def _image(code: bytes, imports: dict[str, list[str]] | None = None) -> tuple[bytes, ImageView]:
    data = build_pe(PESpec(sections=[SectionSpec(".text", code, TEXT)], imports=imports or {}))
    return data, ImageView(data, parse_pe(data))


def test_image_view_reads_by_rva_and_zero_fills_virtual_tail() -> None:
    _, view = _image(b"\xc3\x90")
    assert view.read(TEXT_RVA, 2) == b"\xc3\x90"
    assert view.read(TEXT_RVA + 0x1F0, 4) == b"\x00" * 4
    assert view.read(0x9000_0000, 4) == b""
    assert view.is_executable(TEXT_RVA)


def test_linear_disassembly_from_entry_point() -> None:
    _, view = _image(BRANCHY)
    insns = Disassembler(view).linear(TEXT_RVA, count=4)
    assert [i.mnemonic for i in insns] == ["test", "je", "mov", "ret"]
    assert insns[1].op_str == "0x100b"
    assert insns[0].address == TEXT_RVA and insns[0].size == 3


def test_iat_calls_are_annotated_with_import_names() -> None:
    imports = {"kernel32.dll": ["ExitProcess"]}
    # First pass learns the IAT slot RVA; the layout does not depend on the code bytes.
    probe, _ = _image(b"\x90" * 8, imports)
    [(iat_rva, name)] = parse_pe(probe).import_addresses.items()
    disp = iat_rva - (TEXT_RVA + 6)
    _, view = _image(b"\xff\x15" + struct.pack("<i", disp) + b"\xc3\x90", imports)
    call = Disassembler(view).linear(TEXT_RVA, count=1)[0]
    assert name == "kernel32.dll!ExitProcess"
    assert call.mnemonic == "call"
    assert call.comment == "kernel32.dll!ExitProcess"


def test_build_function_splits_on_conditional_branch() -> None:
    _, view = _image(BRANCHY)
    fn = build_function(Disassembler(view), TEXT_RVA)
    assert sorted(fn.blocks) == [0x1000, 0x1005, 0x100B]
    entry = fn.blocks[0x1000]
    assert {(e.target, e.kind) for e in entry.successors} == {(0x100B, "true"), (0x1005, "false")}
    assert fn.blocks[0x1005].successors == []
    assert fn.calls == [0x1020]


def test_backward_jump_splits_existing_block() -> None:
    _, view = _image(LOOP)
    fn = build_function(Disassembler(view), TEXT_RVA)
    assert sorted(fn.blocks) == [0x1000, 0x1002, 0x1009]
    assert [(e.target, e.kind) for e in fn.blocks[0x1000].successors] == [(0x1002, "fallthrough")]
    assert {(e.target, e.kind) for e in fn.blocks[0x1002].successors} == {
        (0x1002, "true"),
        (0x1009, "false"),
    }
    assert [i.mnemonic for i in fn.blocks[0x1002].instructions] == ["inc", "cmp", "jne"]


def test_indirect_jump_ends_block_without_successors() -> None:
    _, view = _image(bytes.fromhex("FFE0") + b"\xcc")
    fn = build_function(Disassembler(view), TEXT_RVA)
    block = fn.blocks[0x1000]
    assert block.successors == []
    assert block.indirect is True


def test_discover_functions_follows_direct_calls() -> None:
    data, view = _image(BRANCHY)
    functions = discover_functions(Disassembler(view), parse_pe(data))
    assert set(functions) == {0x1000, 0x1020}


def test_function_to_dict_is_serialisable() -> None:
    _, view = _image(BRANCHY)
    d = build_function(Disassembler(view), TEXT_RVA).to_dict()
    assert d["start"] == 0x1000
    assert {b["start"] for b in d["blocks"]} == {0x1000, 0x1005, 0x100B}


NOTEPAD = Path(r"C:\Windows\System32\notepad.exe")


@pytest.mark.skipif(not NOTEPAD.exists(), reason="Windows system binary not available")
def test_real_binary_function_discovery() -> None:
    data = NOTEPAD.read_bytes()
    report = parse_pe(data)
    assert report.function_starts, "x64 .pdata should yield function starts"
    start = time.perf_counter()
    functions = discover_functions(Disassembler(ImageView(data, report)), report)
    assert time.perf_counter() - start < 10
    assert report.entry_point in functions
    assert len(functions) > 100
