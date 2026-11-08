from __future__ import annotations

import struct

from octov.core.analysis.xrefs import XrefIndex
from octov.core.static.cfg import discover_from, discover_functions
from octov.core.static.disasm import Disassembler, ImageView, RawView
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

IMPORTS = {"kernel32.dll": ["ExitProcess"]}
STRING = b"http://x.example/gate.php\x00"


def _code(iat_rva: int) -> bytes:
    # 0x1000: lea rcx, [rip + disp] -> .data string at 0x2000
    lea = bytes.fromhex("488D0D") + struct.pack("<i", 0x2000 - (0x1000 + 7))
    # 0x1007: call 0x1010 ; 0x100c: ret ; pad
    call = bytes.fromhex("E8") + struct.pack("<i", 0x1010 - 0x100C) + b"\xc3" + b"\xcc" * 3
    # 0x1010: call qword ptr [rip + iat] ; ret
    iat_call = bytes.fromhex("FF15") + struct.pack("<i", iat_rva - (0x1010 + 6)) + b"\xc3"
    return lea + call + iat_call


def _sample() -> tuple[bytes, object]:
    probe = build_pe(
        PESpec(
            sections=[SectionSpec(".text", _code(0), TEXT), SectionSpec(".data", STRING, DATA)],
            imports=IMPORTS,
        )
    )
    [iat_rva] = parse_pe(probe).import_addresses
    data = build_pe(
        PESpec(
            sections=[
                SectionSpec(".text", _code(iat_rva), TEXT),
                SectionSpec(".data", STRING, DATA),
            ],
            imports=IMPORTS,
        )
    )
    return data, parse_pe(data)


def test_rip_relative_lea_has_data_ref() -> None:
    data, report = _sample()
    lea = Disassembler(ImageView(data, report)).linear(0x1000, 1)[0]
    assert lea.mnemonic == "lea" and lea.data_ref == 0x2000


def test_branches_have_no_data_ref() -> None:
    data, report = _sample()
    call = Disassembler(ImageView(data, report)).linear(0x1007, 1)[0]
    assert call.is_call and call.data_ref is None


def test_xref_index_data_call_and_import_edges() -> None:
    data, report = _sample()
    functions = discover_functions(Disassembler(ImageView(data, report)), report)
    xrefs = XrefIndex.build(functions, report.import_addresses)
    [data_ref] = xrefs.to(0x2000)
    assert (data_ref.src, data_ref.kind, data_ref.func) == (0x1000, "data", 0x1000)
    assert [(x.src, x.kind) for x in xrefs.to(0x1010)] == [(0x1007, "call")]
    iat_rva = next(iter(report.import_addresses))
    [imp] = xrefs.to(iat_rva)
    assert imp.kind == "import" and imp.func == 0x1010
    assert xrefs.imports_called(0x1010) == ["kernel32.dll!ExitProcess"]
    assert {x.kind for x in xrefs.from_function(0x1000)} == {"data", "call"}


def test_raw_blob_call_xrefs() -> None:
    blob = bytes.fromhex("4885C97406B801000000C331C0E80E000000C3") + b"\xcc" * 13 + b"\xc3"
    functions = discover_from(Disassembler(RawView(blob, bits=64)), [0])
    xrefs = XrefIndex.build(functions, {})
    assert [(x.src, x.kind, x.func) for x in xrefs.to(0x20)] == [(0xD, "call", 0)]
    assert [(x.kind) for x in xrefs.to(0xB)] == ["jump"]
