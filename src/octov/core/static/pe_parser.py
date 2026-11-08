"""Static PE parser: headers, sections, imports/exports, entropy and packing indicators.

pefile is the primary structural parser; LIEF is used for Authenticode
signature inspection. Parsing never executes the sample.

Indicators are *defensive* heuristics mapped to MITRE ATT&CK technique IDs so
they can feed detection content (YARA/Sigma) and analyst triage.
"""

from __future__ import annotations

import hashlib
import io
import struct
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import numpy as np
import pefile

Severity = Literal["info", "low", "medium", "high"]

HIGH_ENTROPY_THRESHOLD = 7.2
MIN_ENTROPY_SECTION_SIZE = 512

_SCN_EXEC = 0x20000000
_SCN_READ = 0x40000000
_SCN_WRITE = 0x80000000

PACKER_SECTION_NAMES: dict[str, str] = {
    "UPX0": "UPX",
    "UPX1": "UPX",
    "UPX2": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".MPRESS1": "MPRESS",
    ".MPRESS2": "MPRESS",
    ".themida": "Themida",
    ".winlice": "WinLicense",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    ".petite": "Petite",
    ".nsp0": "NsPack",
    ".nsp1": "NsPack",
    ".enigma1": "Enigma",
    ".enigma2": "Enigma",
    "PEC2": "PECompact",
    "PECompact2": "PECompact",
    ".packed": "Generic",
    ".perplex": "Perplex",
    ".yP": "Y0da",
}

INJECTION_APIS = frozenset(
    {
        "OpenProcess",
        "VirtualAllocEx",
        "VirtualAlloc2",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtMapViewOfSection",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "NtQueueApcThread",
        "SetThreadContext",
        "NtSetContextThread",
    }
)
_INJECTION_WRITE = frozenset({"WriteProcessMemory", "NtWriteVirtualMemory", "NtMapViewOfSection"})
_INJECTION_EXEC = frozenset(
    {
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "NtQueueApcThread",
        "SetThreadContext",
        "NtSetContextThread",
    }
)
_RESOLVER_LOAD = frozenset({"LoadLibrary", "LoadLibraryEx", "LdrLoadDll", "GetModuleHandle"})
_RESOLVER_GET = frozenset({"GetProcAddress", "LdrGetProcedureAddress"})
ANTI_DEBUG_APIS = frozenset(
    {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
        "NtSetInformationThread",
    }
)
_FEW_IMPORTS = 10


class PEParseError(Exception):
    """Raised when input cannot be read or is not a valid PE image."""


@dataclass(frozen=True)
class Hashes:
    md5: str
    sha1: str
    sha256: str
    imphash: str | None


@dataclass(frozen=True)
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    entropy: float
    characteristics: int

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & _SCN_READ)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & _SCN_WRITE)

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _SCN_EXEC)

    def contains_rva(self, rva: int) -> bool:
        return (
            self.virtual_address
            <= rva
            < self.virtual_address + max(self.virtual_size, self.raw_size)
        )


@dataclass(frozen=True)
class Indicator:
    """A single static finding with evidence suitable for citation in reports."""

    id: str
    severity: Severity
    description: str
    mitre: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SignatureInfo:
    present: bool
    verified: bool | None = None
    signers: list[str] = field(default_factory=list)


@dataclass
class PEReport:
    path: str | None
    size: int
    hashes: Hashes
    machine: str
    is_64bit: bool
    is_dll: bool
    subsystem: str
    timestamp: int
    entry_point: int
    image_base: int
    entropy: float
    sections: list[SectionInfo]
    imports: dict[str, list[str]]
    exports: list[str]
    overlay_offset: int | None
    overlay_size: int
    signature: SignatureInfo
    indicators: list[Indicator] = field(default_factory=list)
    import_addresses: dict[int, str] = field(default_factory=dict)  # IAT slot RVA -> dll!func
    export_rvas: dict[str, int] = field(default_factory=dict)
    function_starts: list[int] = field(default_factory=list)  # from x64 .pdata

    @property
    def compile_time(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp, tz=UTC)

    @property
    def import_count(self) -> int:
        return sum(len(v) for v in self.imports.values())

    def to_dict(self) -> dict[str, Any]:
        """Plain dict (msgpack/JSON serialisable)."""
        data = asdict(self)
        for sec, raw in zip(self.sections, data["sections"], strict=True):
            raw.update(readable=sec.readable, writable=sec.writable, executable=sec.executable)
        # Portable for msgpack/JSON consumers that require string map keys.
        data["import_addresses"] = sorted(
            [rva, name] for rva, name in self.import_addresses.items()
        )
        return data


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-(probs * np.log2(probs)).sum())


def _strip_prefix(value: str, prefix: str) -> str:
    return value[len(prefix) :] if value.startswith(prefix) else value


def _decode(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    return raw.rstrip(b"\x00").decode("latin-1")


def normalize_api(name: str) -> str:
    """Drop the ANSI/Unicode suffix: ``LoadLibraryExW`` -> ``LoadLibraryEx``."""
    return name[:-1] if len(name) > 1 and name[-1] in "AW" and name[-2].islower() else name


def _matches(names: Iterable[str], catalog: frozenset[str]) -> list[str]:
    return sorted({n for n in names if n in catalog or normalize_api(n) in catalog})


def _read_input(source: str | Path | bytes) -> tuple[bytes, str | None]:
    if isinstance(source, bytes | bytearray | memoryview):
        return bytes(source), None
    path = Path(source)
    try:
        return path.read_bytes(), str(path)
    except OSError as exc:
        raise PEParseError(f"cannot read {path}: {exc}") from exc


def _signature_info(pe: pefile.PE, data: bytes) -> SignatureInfo:
    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    if not sec_dir.Size:
        return SignatureInfo(present=False)
    try:
        import lief

        lief.logging.disable()

        binary = lief.PE.parse(io.BytesIO(data))
        if binary is None or not binary.has_signatures:
            return SignatureInfo(present=True, verified=False)
        verified = binary.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK
        signers = [str(signer.issuer) for sig in binary.signatures for signer in sig.signers]
        return SignatureInfo(present=True, verified=verified, signers=signers)
    except Exception:  # LIEF failure must never break triage
        return SignatureInfo(present=True, verified=None)


def parse_pe(source: str | Path | bytes) -> PEReport:
    """Parse a PE file (path or raw bytes) into a :class:`PEReport`."""
    data, path = _read_input(source)
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
    except pefile.PEFormatError as exc:
        raise PEParseError(f"not a valid PE image: {exc}") from exc

    try:
        return _build_report(pe, data, path)
    finally:
        pe.close()


def _build_report(pe: pefile.PE, data: bytes, path: str | None) -> PEReport:
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER

    sections = [
        SectionInfo(
            name=_decode(s.Name),
            virtual_address=s.VirtualAddress,
            virtual_size=s.Misc_VirtualSize,
            raw_offset=s.PointerToRawData,
            raw_size=s.SizeOfRawData,
            entropy=round(shannon_entropy(s.get_data()), 4) if s.SizeOfRawData else 0.0,
            characteristics=s.Characteristics,
        )
        for s in pe.sections
    ]

    imports: dict[str, list[str]] = {}
    import_addresses: dict[int, str] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = _decode(entry.dll).lower()
        funcs = imports.setdefault(dll, [])
        for imp in entry.imports:
            name = _decode(imp.name) if imp.name else f"ord_{imp.ordinal}"
            funcs.append(name)
            if imp.address:
                import_addresses[imp.address - oh.ImageBase] = f"{dll}!{name}"

    exports: list[str] = []
    export_rvas: dict[str, int] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = _decode(sym.name) if sym.name else f"ord_{sym.ordinal}"
            exports.append(name)
            if sym.address and not sym.forwarder:
                export_rvas[name] = sym.address

    overlay_offset = pe.get_overlay_data_start_offset()
    overlay_size = len(data) - overlay_offset if overlay_offset is not None else 0

    imphash: str | None = pe.get_imphash() if imports else None

    report = PEReport(
        path=path,
        size=len(data),
        hashes=Hashes(
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            imphash=imphash or None,
        ),
        machine=_strip_prefix(
            pefile.MACHINE_TYPE.get(fh.Machine, hex(fh.Machine)), "IMAGE_FILE_MACHINE_"
        ),
        is_64bit=oh.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS,
        is_dll=pe.is_dll(),
        subsystem=_strip_prefix(
            pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem)), "IMAGE_SUBSYSTEM_"
        ),
        timestamp=fh.TimeDateStamp,
        entry_point=oh.AddressOfEntryPoint,
        image_base=oh.ImageBase,
        entropy=round(shannon_entropy(data), 4),
        sections=sections,
        imports=imports,
        exports=exports,
        overlay_offset=overlay_offset,
        overlay_size=overlay_size,
        signature=_signature_info(pe, data),
        import_addresses=import_addresses,
        export_rvas=export_rvas,
        function_starts=_pdata_function_starts(pe, fh.Machine),
    )
    report.indicators = list(_indicators(report, data))
    return report


def _pdata_function_starts(pe: pefile.PE, machine: int) -> list[int]:
    """Function begin RVAs from the x64 exception directory (RUNTIME_FUNCTION entries)."""
    if machine != 0x8664:
        return []
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]
    ]
    if not entry.VirtualAddress or not entry.Size:
        return []
    try:
        raw = pe.get_data(entry.VirtualAddress, entry.Size)
    except pefile.PEFormatError:
        return []
    usable = len(raw) - len(raw) % 12
    return sorted(
        {begin for begin, _end, _unwind in struct.iter_unpack("<III", raw[:usable]) if begin}
    )


def _indicators(r: PEReport, data: bytes) -> Iterable[Indicator]:
    packing = ["T1027.002"]

    for sec in r.sections:
        if sec.raw_size >= MIN_ENTROPY_SECTION_SIZE and sec.entropy >= HIGH_ENTROPY_THRESHOLD:
            yield Indicator(
                "high_entropy_section",
                "medium",
                f"Section {sec.name!r} has high entropy ({sec.entropy:.2f}); "
                "likely compressed or encrypted content.",
                packing,
                {"section": sec.name, "entropy": sec.entropy, "raw_offset": sec.raw_offset},
            )
        if sec.writable and sec.executable:
            yield Indicator(
                "rwx_section",
                "medium",
                f"Section {sec.name!r} is writable and executable (self-modifying/unpacking stub).",
                packing,
                {"section": sec.name, "characteristics": hex(sec.characteristics)},
            )
        if sec.name in PACKER_SECTION_NAMES:
            yield Indicator(
                "packer_section_name",
                "medium",
                f"Section name {sec.name!r} is associated with {PACKER_SECTION_NAMES[sec.name]}.",
                packing,
                {"section": sec.name, "packer": PACKER_SECTION_NAMES[sec.name]},
            )
        if sec.virtual_size >= 0x1000 and (
            sec.raw_size == 0 or sec.virtual_size > sec.raw_size * 10
        ):
            yield Indicator(
                "virtual_size_inflated",
                "low",
                f"Section {sec.name!r} reserves far more memory than it stores on disk "
                "(typical unpacking destination).",
                packing,
                {"section": sec.name, "virtual_size": sec.virtual_size, "raw_size": sec.raw_size},
            )

    ep_section = next((s for s in r.sections if s.contains_rva(r.entry_point)), None)
    if r.entry_point and ep_section is None:
        yield Indicator(
            "entry_point_outside_sections",
            "high",
            "Entry point does not fall inside any section.",
            ["T1027"],
            {"entry_point": hex(r.entry_point)},
        )
    elif ep_section is not None and not ep_section.executable:
        yield Indicator(
            "entry_point_not_executable",
            "high",
            f"Entry point lies in non-executable section {ep_section.name!r}.",
            ["T1027"],
            {"entry_point": hex(r.entry_point), "section": ep_section.name},
        )

    all_funcs = [f for funcs in r.imports.values() for f in funcs]
    if not r.imports and not r.is_dll:
        yield Indicator(
            "no_imports",
            "medium",
            "Executable has no import table; APIs are likely resolved at runtime.",
            ["T1027.007"],
            {},
        )
    loaders = _matches(all_funcs, _RESOLVER_LOAD)
    getters = _matches(all_funcs, _RESOLVER_GET)
    if loaders and getters and len(all_funcs) < _FEW_IMPORTS:
        yield Indicator(
            "dynamic_api_resolution",
            "medium",
            f"Only {len(all_funcs)} imports including a loader/resolver pair; "
            "remaining APIs are probably resolved dynamically.",
            ["T1027.007", "T1106"],
            {"apis": loaders + getters, "import_count": len(all_funcs)},
        )

    injection = _matches(all_funcs, INJECTION_APIS)
    if _matches(injection, _INJECTION_WRITE) and _matches(injection, _INJECTION_EXEC):
        yield Indicator(
            "process_injection_apis",
            "medium",
            "Imports a cross-process memory write primitive together with a remote "
            "execution primitive (process injection capability).",
            ["T1055"],
            {"apis": injection},
        )

    anti_debug = _matches(all_funcs, ANTI_DEBUG_APIS)
    if anti_debug:
        yield Indicator(
            "anti_debug_apis",
            "low",
            "Imports APIs commonly used for debugger detection.",
            ["T1622"],
            {"apis": anti_debug},
        )

    if r.overlay_offset is not None and r.overlay_size:
        overlay = data[r.overlay_offset :]
        yield Indicator(
            "overlay_present",
            "low",
            f"{r.overlay_size} bytes of data appended after the last section.",
            [],
            {
                "offset": r.overlay_offset,
                "size": r.overlay_size,
                "entropy": round(shannon_entropy(overlay), 4),
            },
        )

    now = datetime.now(tz=UTC).timestamp()
    if r.timestamp == 0 or r.timestamp > now + 86400:
        yield Indicator(
            "suspicious_timestamp",
            "low",
            "PE compile timestamp is zero or in the future (possible timestomping).",
            ["T1070.006"],
            {"timestamp": r.timestamp},
        )
