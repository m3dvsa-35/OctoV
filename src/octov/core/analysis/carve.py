"""Embedded payload carving: PE files hidden in overlays/resources/sections, opaque blobs.

Carved bytes never touch the disk as executables: they live in memory / the
session, and the only export is an AES-encrypted ZIP with the conventional
password ``infected``.
"""

from __future__ import annotations

import hashlib
import io
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

import pefile
import pyzipper

from octov.core.analysis.facts import Evidence, Fact
from octov.core.static.pe_parser import PEReport, shannon_entropy

ZIP_PASSWORD = b"infected"
MIN_BLOB = 4096
HIGH_ENTROPY = 7.2
_KNOWN_MEDIA = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM", b"RIFF", b"\x00\x00\x01\x00")


@dataclass(frozen=True)
class Payload:
    offset: int
    size: int
    kind: Literal["pe", "high_entropy"]
    where: str
    sha256: str


def _embedded_pe_size(data: bytes, pos: int) -> int | None:
    """Size of a PE starting at ``pos`` or ``None`` if the header is not a valid PE."""
    if pos + 0x40 > len(data):
        return None
    (e_lfanew,) = struct.unpack_from("<I", data, pos + 0x3C)
    nt = pos + e_lfanew
    if not 0x40 <= e_lfanew < 0x1000 or nt + 24 > len(data) or data[nt : nt + 4] != b"PE\x00\x00":
        return None
    (n_sections,) = struct.unpack_from("<H", data, nt + 6)
    (opt_size,) = struct.unpack_from("<H", data, nt + 20)
    table = nt + 24 + opt_size
    if n_sections == 0 or n_sections > 96 or table + 40 * n_sections > len(data):
        return None
    end = table + 40 * n_sections
    for i in range(n_sections):
        raw_size, raw_ptr = struct.unpack_from("<II", data, table + 40 * i + 16)
        if raw_size:
            end = max(end, raw_ptr + raw_size)
    return min(end, len(data) - pos)


def _where(report: PEReport | None, offset: int) -> str:
    if report is None:
        return "offset"
    if report.overlay_offset is not None and offset >= report.overlay_offset:
        return "overlay"
    for s in report.sections:
        if s.raw_size and s.raw_offset <= offset < s.raw_offset + s.raw_size:
            return f"section:{s.name}"
    return "offset"


def _resource_blobs(data: bytes) -> list[tuple[int, int, str]]:
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
    except pefile.PEFormatError:
        return []
    out: list[tuple[int, int, str]] = []
    for rtype in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []):
        tname = str(rtype.name) if rtype.name else pefile.RESOURCE_TYPE.get(rtype.id, str(rtype.id))
        for entry in getattr(getattr(rtype, "directory", None), "entries", []):
            for leaf in getattr(getattr(entry, "directory", None), "entries", []):
                struct_ = getattr(getattr(leaf, "data", None), "struct", None)
                if struct_ is None:
                    continue
                try:
                    offset = pe.get_offset_from_rva(struct_.OffsetToData)
                except pefile.PEFormatError:
                    continue
                name = str(entry.name) if entry.name else str(entry.id)
                out.append((offset, struct_.Size, f"resource:{tname}/{name}"))
    pe.close()
    return out


def carve_payloads(data: bytes, report: PEReport | None) -> list[Payload]:
    payloads: list[Payload] = []
    covered: list[tuple[int, int]] = []
    pos = data.find(b"MZ", 1)
    while pos != -1:
        size = _embedded_pe_size(data, pos)
        if size and not any(a <= pos < b for a, b in covered):
            blob = data[pos : pos + size]
            payloads.append(
                Payload(pos, size, "pe", _where(report, pos), hashlib.sha256(blob).hexdigest())
            )
            covered.append((pos, pos + size))
        pos = data.find(b"MZ", pos + 2)

    if report is not None:
        for offset, size, where in _resource_blobs(data):
            blob = data[offset : offset + size]
            if (
                size >= MIN_BLOB
                and not any(a <= offset < b for a, b in covered)
                and not blob.startswith(_KNOWN_MEDIA)
                and shannon_entropy(blob) >= HIGH_ENTROPY
            ):
                payloads.append(
                    Payload(offset, size, "high_entropy", where, hashlib.sha256(blob).hexdigest())
                )
    return sorted(payloads, key=lambda p: p.offset)


def payload_facts(payloads: Sequence[Payload]) -> list[Fact]:
    return [
        Fact(
            kind="embedded_payload",
            source_id=p.kind,
            severity="medium" if p.kind == "pe" else "low",
            title=(
                f"Embedded PE file ({p.size:,} bytes) in {p.where}"
                if p.kind == "pe"
                else f"High-entropy blob ({p.size:,} bytes) in {p.where}"
            ),
            evidence=(Evidence(f"sha256 {p.sha256}", offset=p.offset, value=p.sha256),),
            mitre=("T1027.009",) if p.kind == "pe" else ("T1027",),
            explain_key="fact.embedded_payload",
        )
        for p in payloads
    ]


def payload_zip(data: bytes, name: str) -> bytes:
    """AES-256 encrypted ZIP containing ``data`` as ``name`` (password ``infected``)."""
    buf = io.BytesIO()
    with pyzipper.AESZipFile(
        buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(ZIP_PASSWORD)
        zf.writestr(name, data)
    return buf.getvalue()
