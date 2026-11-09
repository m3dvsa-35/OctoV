"""Well-known cryptographic / checksum constants embedded in a binary.

These tables tell an analyst *which* algorithm a sample likely implements
(ransomware AES, RC4-style config decryption, CRC checks, ...). They are
weak signals on their own, so every hit is a low-severity fact.
"""

from __future__ import annotations

from dataclasses import dataclass

from octov.core.analysis.facts import Evidence, Fact
from octov.core.static.pe_parser import PEReport

MAX_HITS_PER_SIG = 8


@dataclass(frozen=True)
class CryptoSig:
    name: str
    family: str
    pattern: bytes


CRYPTO_SIGNATURES: tuple[CryptoSig, ...] = (
    CryptoSig("AES S-box", "aes", bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    CryptoSig("AES inverse S-box", "aes", bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    CryptoSig("AES Te0", "aes", bytes.fromhex("c66363a5f87c7c84ee777799f67b7b8d")),
    CryptoSig("SHA-256 K", "sha256", bytes.fromhex("982f8a42914437712fb7c0b5a5dbb5e9")),
    CryptoSig("SHA-1 init", "sha1", bytes.fromhex("0123456789abcdeffedcba9876543210f0e1d2c3")),
    CryptoSig("MD5 T", "md5", bytes.fromhex("78a46ad756b7c7e8db702024eecebdc1")),
    CryptoSig("CRC32 table", "crc32", bytes.fromhex("00000000963007772c610eeeba51099919c46d07")),
    CryptoSig("Blowfish P", "blowfish", bytes.fromhex("886a3f24d308a3852e8a191344737003")),
    CryptoSig("ChaCha/Salsa sigma", "chacha", b"expand 32-byte k"),
    CryptoSig("TEA delta", "tea", bytes.fromhex("b979379e")),
)


def _locate(report: PEReport | None, offset: int) -> int | None:
    if report is None:
        return None
    for s in report.sections:
        if s.raw_size and s.raw_offset <= offset < s.raw_offset + s.raw_size:
            return s.virtual_address + (offset - s.raw_offset)
    return None


def find_crypto(data: bytes, report: PEReport | None) -> list[Fact]:
    facts: list[Fact] = []
    for sig in CRYPTO_SIGNATURES:
        hits: list[Evidence] = []
        pos = data.find(sig.pattern)
        while pos != -1 and len(hits) < MAX_HITS_PER_SIG:
            hits.append(Evidence(f"{sig.name} constant", offset=pos, rva=_locate(report, pos)))
            pos = data.find(sig.pattern, pos + len(sig.pattern))
        if hits:
            facts.append(
                Fact(
                    kind="crypto_constant",
                    source_id=sig.name,
                    severity="low",
                    title=f"{sig.name} constants ({sig.family.upper()})",
                    evidence=tuple(hits),
                    tags=(sig.family,),
                    explain_key="fact.crypto_constant",
                )
            )
    return facts
