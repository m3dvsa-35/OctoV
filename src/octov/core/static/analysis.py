"""Static analysis pipeline: PE parsing + technique rule matching (PE or raw blobs)."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from functools import cache
from pathlib import Path
from typing import Any

from octov.core.config import RulesConfig
from octov.core.static.pe_parser import (
    Hashes,
    PEParseError,
    PEReport,
    parse_pe,
    shannon_entropy,
)
from octov.core.static.rules import Finding, Rule, RuleEngine, load_rules


@dataclass
class StaticAnalysis:
    report: PEReport
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        data = self.report.to_dict()
        data["format"] = "pe"
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


@dataclass
class RawSample:
    """A non-PE code blob (e.g. shellcode carved from memory or a document)."""

    path: str | None
    size: int
    hashes: Hashes
    entropy: float
    bits: int


@dataclass
class RawAnalysis:
    sample: RawSample
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self.sample)
        data["format"] = "raw"
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


@cache
def _cached_rule_set(paths: tuple[Path, ...]) -> tuple[Rule, ...]:
    return tuple(load_rules(paths))


def rule_set(paths: Sequence[str | Path]) -> tuple[Rule, ...]:
    """Load (and cache) the rules from ``paths`` as one set, so IDs must be unique across files."""
    return _cached_rule_set(tuple(Path(p).resolve() for p in paths))


def default_rules() -> tuple[Rule, ...]:
    return rule_set(RulesConfig().paths)


def analyze(source: str | Path | bytes, rules: Sequence[Rule] | None = None) -> StaticAnalysis:
    """Parse ``source`` and match technique rules (shipped catalogs by default)."""
    if isinstance(source, bytes | bytearray | memoryview):
        data = bytes(source)
    else:
        try:
            data = Path(source).read_bytes()
        except OSError as exc:
            raise PEParseError(f"cannot read {source}: {exc}") from exc
    report = parse_pe(data)
    if not isinstance(source, bytes | bytearray | memoryview):
        report.path = str(source)
    engine = RuleEngine(default_rules() if rules is None else rules)
    return StaticAnalysis(report, engine.scan(data, report))


def analyze_raw(
    source: str | Path | bytes, rules: Sequence[Rule] | None = None, bits: int = 64
) -> RawAnalysis:
    """Match technique rules against a raw blob. Only byte/string indicators can match."""
    if bits not in (32, 64):
        raise ValueError("bits must be 32 or 64")
    path: str | None = None
    if isinstance(source, bytes | bytearray | memoryview):
        data = bytes(source)
    else:
        path = str(source)
        try:
            data = Path(source).read_bytes()
        except OSError as exc:
            raise PEParseError(f"cannot read {source}: {exc}") from exc
    sample = RawSample(
        path=path,
        size=len(data),
        hashes=Hashes(
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            imphash=None,
        ),
        entropy=round(shannon_entropy(data), 4),
        bits=bits,
    )
    engine = RuleEngine(default_rules() if rules is None else rules)
    return RawAnalysis(sample, engine.scan(data, None))
