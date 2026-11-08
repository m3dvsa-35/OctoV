"""String extraction (ASCII + UTF-16LE) with IOC-oriented classification."""

from __future__ import annotations

import bisect
import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

from octov.core.static.pe_parser import PEReport

MAX_STRINGS = 200_000

_ASCII = re.compile(rb"[\x20-\x7e]{%d,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")

# File extensions that make "name.ext" a file name, never a domain.
_FILE_EXT = frozenset(
    [
        "dll",
        "exe",
        "sys",
        "ocx",
        "drv",
        "cpl",
        "scr",
        "tmp",
        "dat",
        "txt",
        "ini",
        "log",
        "pdb",
        "mui",
        "cat",
        "manifest",
        "xml",
        "json",
        "png",
        "jpg",
        "gif",
        "bmp",
        "ico",
        "cfg",
        "bin",
        "lib",
        "obj",
        "cpp",
        "h",
        "c",
        "py",
        "js",
        "cs",
        "vbs",
        "bat",
        "cmd",
        "ps1",
        "lnk",
        "inf",
        "msi",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "pdf",
        "zip",
        "rar",
        "7z",
        "htm",
        "html",
        "css",
    ]
)

_URL = re.compile(r"^(?:https?|ftp)://[^\s/$.?#][^\s]*$", re.I)
_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)
_REGISTRY = re.compile(
    r"^(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)(?:\\|$)|^(?:SOFTWARE|SYSTEM\\CurrentControlSet)\\", re.I
)
_PATH = re.compile(r"^(?:[A-Za-z]:\\|\\\\[\w.$-]+\\|%[A-Za-z]+%\\)")
_MUTEX = re.compile(r"^(?:Global|Local|Session\\\d+)\\[\w.{}-]{3,}$")
_USER_AGENT = re.compile(r"^Mozilla/\d\.\d")
_COMMAND = re.compile(
    r"^(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?\s+/[ck]|rundll32|regsvr32|mshta|schtasks|wmic|"
    r"certutil(?:\.exe)?\s+-|bitsadmin|vssadmin|bcdedit|net\s+(?:user|localgroup))\b",
    re.I,
)
_WALLET = re.compile(
    r"^(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})$"
)
_BASE64 = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")


@dataclass(frozen=True)
class FoundString:
    value: str
    encoding: Literal["ascii", "utf16"]
    offset: int
    rva: int | None
    section: str | None
    category: str | None


def _is_ip(value: str) -> bool:
    if not _IPV4.match(value):
        return False
    octets = [int(x) for x in value.split(".")]
    # Reject version-like quads such as 1.2.3.4 and invalid octets.
    return all(o <= 255 for o in octets) and any(o > 9 for o in octets)


def classify(value: str) -> str | None:
    """Return the IOC category of ``value`` or ``None``."""
    v = value.strip()
    if len(v) < 4:
        return None
    if _URL.match(v):
        return "url"
    if _EMAIL.match(v):
        return "email"
    if _is_ip(v):
        return "ipv4"
    if v.count(":") >= 2 and " " not in v:
        try:
            if ipaddress.ip_address(v).version == 6:
                return "ipv6"
        except ValueError:
            pass
    if _REGISTRY.match(v):
        return "registry"
    if _PATH.match(v):
        return "path"
    if _MUTEX.match(v):
        return "mutex"
    if _USER_AGENT.match(v):
        return "user_agent"
    if _COMMAND.match(v):
        return "command"
    if _WALLET.match(v):
        return "wallet"
    tld = v.rsplit(".", 1)[-1]
    # PascalCase last label = .NET/WinRT namespace (Windows.Storage.StorageFile), not a host.
    if _DOMAIN.match(v) and tld.lower() not in _FILE_EXT and tld.islower():
        return "domain"
    if (
        _BASE64.match(v)
        and len(v) % 4 == 0
        and any(c.isdigit() or c in "+/=" for c in v)
        and any(c.islower() for c in v)
        and any(c.isupper() for c in v)
    ):
        return "base64"
    return None


def extract_strings(data: bytes, report: PEReport | None, min_len: int = 4) -> list[FoundString]:
    """All printable ASCII and UTF-16LE runs of at least ``min_len`` characters, by offset."""
    sections = sorted(
        (s for s in (report.sections if report else []) if s.raw_size),
        key=lambda s: s.raw_offset,
    )
    starts = [s.raw_offset for s in sections]

    def locate(offset: int) -> tuple[int | None, str | None]:
        idx = bisect.bisect_right(starts, offset) - 1
        if idx >= 0:
            sec = sections[idx]
            if offset < sec.raw_offset + sec.raw_size:
                return sec.virtual_address + (offset - sec.raw_offset), sec.name
        return None, None

    hits: list[tuple[int, str, Literal["ascii", "utf16"]]] = []
    for m in re.compile(_ASCII.pattern % min_len).finditer(data):
        hits.append((m.start(), m.group().decode("ascii"), "ascii"))
    for m in re.compile(_UTF16.pattern % min_len).finditer(data):
        start, raw = m.start(), m.group()
        # A run that starts right after printable text began on the tail of an ASCII
        # string (e.g. 'php' + NUL + 'G' + NUL ...): drop that borrowed first character.
        if start > 0 and 0x20 <= data[start - 1] <= 0x7E:
            start, raw = start + 2, raw[2:]
        if len(raw) // 2 >= min_len:
            hits.append((start, raw.decode("utf-16-le"), "utf16"))
    hits.sort(key=lambda h: h[0])

    out: list[FoundString] = []
    for offset, value, encoding in hits[:MAX_STRINGS]:
        rva, section = locate(offset)
        out.append(FoundString(value, encoding, offset, rva, section, classify(value)))
    return out
