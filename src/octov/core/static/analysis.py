"""Static analysis pipeline: PE parsing + technique rule matching."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from octov.core.config import RulesConfig
from octov.core.static.pe_parser import PEParseError, PEReport, parse_pe
from octov.core.static.rules import Finding, Rule, RuleEngine, load_rules


@dataclass
class StaticAnalysis:
    report: PEReport
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        data = self.report.to_dict()
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


@cache
def default_rules() -> tuple[Rule, ...]:
    return tuple(load_rules(RulesConfig().paths))


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
