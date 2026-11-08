from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest
import pyzipper

from octov.core.analysis.carve import carve_payloads, payload_facts, payload_zip
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import PESpec, build_pe

INNER = build_pe(PESpec(imports={"kernel32.dll": ["ExitProcess"]}))


def test_pe_in_overlay_is_carved_with_size_and_hash() -> None:
    outer = build_pe(PESpec(overlay=b"\x00" * 16 + INNER + b"TRAILER"))
    report = parse_pe(outer)
    [payload] = carve_payloads(outer, report)
    assert payload.kind == "pe"
    assert payload.offset == report.overlay_offset + 16
    assert payload.size == len(INNER)
    assert payload.sha256 == hashlib.sha256(INNER).hexdigest()
    assert payload.where == "overlay"


def test_payload_facts_have_locations() -> None:
    outer = build_pe(PESpec(overlay=INNER))
    report = parse_pe(outer)
    [fact] = payload_facts(carve_payloads(outer, report))
    assert fact.kind == "embedded_payload" and fact.severity == "medium"
    assert fact.evidence[0].offset == report.overlay_offset
    assert fact.explain_key == "fact.embedded_payload"


@pytest.mark.parametrize(
    "tail",
    [
        b"MZ",  # truncated at end of file
        b"MZ" + b"\x00" * 58 + b"\xff\xff\xff\x7f",  # bogus e_lfanew
        b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"NOPE",  # no PE signature
    ],
)
def test_malformed_embedded_headers_are_ignored(tail: bytes) -> None:
    outer = build_pe(PESpec(overlay=tail))
    assert carve_payloads(outer, parse_pe(outer)) == []


def test_raw_blob_containing_pe() -> None:
    blob = b"\x90" * 100 + INNER
    [payload] = carve_payloads(blob, None)
    assert (payload.offset, payload.size, payload.where) == (100, len(INNER), "offset")


def test_payload_zip_is_encrypted_with_infected() -> None:
    archive = payload_zip(INNER, "inner.bin")
    with pyzipper.AESZipFile(io.BytesIO(archive)) as zf:
        with pytest.raises(RuntimeError):
            zf.read("inner.bin")
        zf.setpassword(b"infected")
        assert zf.read("inner.bin") == INNER
    assert INNER[:64] not in archive  # stored encrypted: no plaintext PE header in the file


SHELL32 = Path(r"C:\Windows\System32\shell32.dll")


@pytest.mark.skipif(not SHELL32.exists(), reason="Windows system binary not available")
def test_images_in_resources_are_not_reported() -> None:
    data = SHELL32.read_bytes()
    payloads = carve_payloads(data, parse_pe(data))
    assert all(
        p.kind != "high_entropy" or data[p.offset : p.offset + 4] != b"\x89PNG" for p in payloads
    )
