from __future__ import annotations

import pytest

from octov.core.analysis.crypto import CRYPTO_SIGNATURES, find_crypto
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import RDATA, TEXT, PESpec, SectionSpec, build_pe

REQUIRED = {
    "AES S-box",
    "AES Te0",
    "SHA-256 K",
    "MD5 T",
    "CRC32 table",
    "Blowfish P",
    "ChaCha/Salsa sigma",
}


def test_required_signatures_present() -> None:
    assert {s.name for s in CRYPTO_SIGNATURES} >= REQUIRED


@pytest.mark.parametrize("sig", CRYPTO_SIGNATURES, ids=lambda s: s.name)
def test_each_signature_is_found_with_location(sig) -> None:  # type: ignore[no-untyped-def]
    blob = b"\x00" * 32 + sig.pattern + b"\x00" * 32
    data = build_pe(
        PESpec(sections=[SectionSpec(".text", b"\xc3", TEXT), SectionSpec(".rdata", blob, RDATA)])
    )
    report = parse_pe(data)
    facts = [f for f in find_crypto(data, report) if f.source_id == sig.name]
    assert len(facts) == 1
    [ev] = facts[0].evidence
    rdata = report.sections[1]
    assert ev.offset == rdata.raw_offset + 32 and ev.rva == rdata.virtual_address + 32
    assert facts[0].kind == "crypto_constant" and facts[0].severity == "low"
    assert facts[0].tags == (sig.family,) and facts[0].explain_key == "fact.crypto_constant"


def test_absent_constants_yield_nothing() -> None:
    assert find_crypto(build_pe(), parse_pe(build_pe())) == []


def test_repeated_table_is_one_fact_with_two_locations() -> None:
    sig = CRYPTO_SIGNATURES[0]
    data = b"\x00" * 8 + sig.pattern + b"\x00" * 64 + sig.pattern
    [fact] = [f for f in find_crypto(data, None) if f.source_id == sig.name]
    assert [e.offset for e in fact.evidence] == [8, 8 + len(sig.pattern) + 64]
    assert all(e.rva is None for e in fact.evidence)
