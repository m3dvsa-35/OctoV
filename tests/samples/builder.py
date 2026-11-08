"""Synthetic PE32+ builder for tests.

Generates small, *benign* Windows PE images in memory so the test suite never
needs real malware. Every structure is laid out by hand so tests can control
exactly which static indicators are present (section names/permissions,
entropy, imports, overlay, ...). The generated files contain no executable
logic beyond a single `ret` instruction by default.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
HEADERS_SIZE = 0x400
IMAGE_BASE = 0x140000000

SCN_CODE = 0x00000020
SCN_INIT_DATA = 0x00000040
SCN_EXEC = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000

TEXT = SCN_CODE | SCN_EXEC | SCN_READ
RDATA = SCN_INIT_DATA | SCN_READ
DATA = SCN_INIT_DATA | SCN_READ | SCN_WRITE
RWX = SCN_CODE | SCN_EXEC | SCN_READ | SCN_WRITE


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass
class SectionSpec:
    name: str
    data: bytes
    characteristics: int
    virtual_size: int | None = None


@dataclass
class PESpec:
    sections: list[SectionSpec] = field(
        default_factory=lambda: [SectionSpec(".text", b"\xc3" + b"\x90" * 15, TEXT)]
    )
    imports: dict[str, list[str]] = field(default_factory=dict)
    entry_section: int = 0
    entry_offset: int = 0
    is_dll: bool = False
    overlay: bytes = b""
    timestamp: int = 0x65000000


def _build_imports(rva: int, imports: dict[str, list[str]]) -> tuple[bytes, int, int, int, int]:
    """Return (blob, import_dir_rva, import_dir_size, iat_rva, iat_size)."""
    dlls = list(imports.items())
    desc_size = (len(dlls) + 1) * 20
    offset = desc_size
    thunk_offsets: list[tuple[int, int]] = []
    for _, funcs in dlls:
        table = (len(funcs) + 1) * 8
        ilt, iat = offset, offset + table
        thunk_offsets.append((ilt, iat))
        offset += 2 * table
    iat_start = thunk_offsets[0][1] if dlls else 0
    iat_end = (thunk_offsets[-1][1] + (len(dlls[-1][1]) + 1) * 8) if dlls else 0

    names = bytearray()
    names_base = offset
    func_rvas: list[list[int]] = []
    dll_name_rvas: list[int] = []
    for dll, funcs in dlls:
        rvas = []
        for func in funcs:
            rvas.append(rva + names_base + len(names))
            names += struct.pack("<H", 0) + func.encode() + b"\x00"
            if len(names) % 2:
                names += b"\x00"
        func_rvas.append(rvas)
        dll_name_rvas.append(rva + names_base + len(names))
        names += dll.encode() + b"\x00"
        if len(names) % 2:
            names += b"\x00"

    blob = bytearray(names_base) + names
    for i, ((ilt, iat), rvas) in enumerate(zip(thunk_offsets, func_rvas, strict=True)):
        struct.pack_into("<IIIII", blob, i * 20, rva + ilt, 0, 0, dll_name_rvas[i], rva + iat)
        for j, name_rva in enumerate(rvas):
            struct.pack_into("<Q", blob, ilt + j * 8, name_rva)
            struct.pack_into("<Q", blob, iat + j * 8, name_rva)
    return bytes(blob), rva, desc_size, rva + iat_start, iat_end - iat_start


def build_pe(spec: PESpec | None = None) -> bytes:
    spec = spec or PESpec()
    sections = list(spec.sections)

    # Assign RVAs; the import section (if any) is appended last.
    rvas: list[int] = []
    next_rva = SECT_ALIGN
    for sec in sections:
        rvas.append(next_rva)
        vsize = sec.virtual_size if sec.virtual_size is not None else len(sec.data)
        next_rva += _align(max(vsize, 1), SECT_ALIGN)

    import_dir = (0, 0)
    iat_dir = (0, 0)
    if spec.imports:
        blob, irva, isize, iat_rva, iat_size = _build_imports(next_rva, spec.imports)
        sections.append(SectionSpec(".idata", blob, RDATA))
        rvas.append(next_rva)
        next_rva += _align(len(blob), SECT_ALIGN)
        import_dir, iat_dir = (irva, isize), (iat_rva, iat_size)

    size_of_image = next_rva
    entry_point = rvas[spec.entry_section] + spec.entry_offset

    # Raw layout
    raw_ptr = HEADERS_SIZE
    headers_tbl = bytearray()
    body = bytearray()
    for sec, rva in zip(sections, rvas, strict=True):
        raw_size = _align(len(sec.data), FILE_ALIGN) if sec.data else 0
        vsize = sec.virtual_size if sec.virtual_size is not None else len(sec.data)
        headers_tbl += struct.pack(
            "<8sIIIIIIHHI",
            sec.name.encode()[:8],
            vsize,
            rva,
            raw_size,
            raw_ptr if raw_size else 0,
            0,
            0,
            0,
            0,
            sec.characteristics,
        )
        body += sec.data.ljust(raw_size, b"\x00")
        raw_ptr += raw_size

    data_dirs = [(0, 0)] * 16
    data_dirs[1] = import_dir
    data_dirs[12] = iat_dir

    code_size = sum(len(s.data) for s in sections if s.characteristics & SCN_CODE)
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # PE32+
        14,
        0,
        code_size,
        0,
        0,
        entry_point,
        rvas[0],
        IMAGE_BASE,
        SECT_ALIGN,
        FILE_ALIGN,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        size_of_image,
        HEADERS_SIZE,
        0,
        3,  # IMAGE_SUBSYSTEM_WINDOWS_CUI
        0x8160,  # NX_COMPAT | DYNAMIC_BASE | HIGH_ENTROPY_VA | TERMINAL_SERVER_AWARE
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional += b"".join(struct.pack("<II", *d) for d in data_dirs)

    characteristics = 0x0022 | (0x2000 if spec.is_dll else 0)
    coff = struct.pack(
        "<HHIIIHH", 0x8664, len(sections), spec.timestamp, 0, 0, len(optional), characteristics
    )

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    headers = bytes(dos) + b"PE\x00\x00" + coff + optional + bytes(headers_tbl)
    assert len(headers) <= HEADERS_SIZE, "too many sections for header area"
    return headers.ljust(HEADERS_SIZE, b"\x00") + bytes(body) + spec.overlay
