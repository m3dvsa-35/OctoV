"""Static detection rule engine for the YAML technique catalogs in ``rules/``.

Rule schema (see ``rules/evasion_patterns.yaml``)::

    - id: EVA-001
      name: ...
      description: ...
      severity: info | low | medium | high
      mitre: [T1106]
      condition: any | all | <int>        # how many indicators must match
      indicators:
        - { type: bytes,   value: "4C 8B D1 B8 ?? ?? 00 00 0F 05" }   # '?' = wildcard nibble
        - { type: string,  value: "AmsiScanBuffer" }                  # ASCII or UTF-16LE
        - { type: import,  value: CreateProcess }                     # A/W suffix ignored
        - { type: export,  value: NtClose }
        - { type: section, value: .vmp0 }
      unless:                              # optional: any match suppresses the rule
        - { type: export, value: NtClose }

Every match records the file offset (and RVA when it falls inside a section)
so downstream reports and AI summaries can cite exact evidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from octov.core.static.pe_parser import PEReport, Severity, normalize_api

INDICATOR_TYPES = frozenset({"bytes", "string", "import", "export", "section"})
SEVERITIES = ("info", "low", "medium", "high")
_MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")
_HEX_TOKEN = re.compile(r"^[0-9A-Fa-f?]{2}$")
MAX_MATCHES_PER_INDICATOR = 5

Condition = str | int


class RuleError(Exception):
    """Invalid rule file, rule definition or byte pattern."""


@dataclass(frozen=True)
class IndicatorSpec:
    type: str
    value: str


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    severity: Severity
    mitre: list[str]
    condition: Condition
    indicators: list[IndicatorSpec]
    unless: list[IndicatorSpec] = field(default_factory=list)
    source: str | None = None


@dataclass(frozen=True)
class Match:
    type: str
    value: str
    detail: str
    offset: int | None = None
    rva: int | None = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    name: str
    severity: Severity
    mitre: list[str]
    description: str
    matches: list[Match]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# -- patterns -------------------------------------------------------------------


def _nibble_class(token: str) -> bytes:
    hi, lo = token[0], token[1]
    his = range(16) if hi == "?" else [int(hi, 16)]
    los = range(16) if lo == "?" else [int(lo, 16)]
    values = sorted(h << 4 | low for h in his for low in los)
    return b"[" + b"".join(re.escape(bytes([v])) for v in values) + b"]"


def compile_pattern(pattern: str) -> re.Pattern[bytes]:
    """Compile ``"4C 8B ?? 5?"``-style hex patterns to a bytes regex."""
    tokens = pattern.split(" ")
    if not pattern or any(not _HEX_TOKEN.match(t) for t in tokens):
        raise RuleError(f"invalid byte pattern: {pattern!r}")
    parts: list[bytes] = []
    for tok in tokens:
        if tok == "??":
            parts.append(b".")
        elif "?" in tok:
            parts.append(_nibble_class(tok))
        else:
            parts.append(re.escape(bytes([int(tok, 16)])))
    return re.compile(b"".join(parts), re.DOTALL)


def required_matches(condition: Condition, total: int) -> int:
    if condition == "any":
        return 1
    if condition == "all":
        return total
    if isinstance(condition, int) and not isinstance(condition, bool):
        return condition
    raise RuleError(f"invalid condition: {condition!r}")


# -- loading --------------------------------------------------------------------


def _indicators(raw: Any, rule_id: str, key: str) -> list[IndicatorSpec]:
    if raw is None and key == "unless":
        return []
    if not isinstance(raw, list) or (key == "indicators" and not raw):
        raise RuleError(f"{rule_id}: '{key}' must be a non-empty list")
    specs = []
    for item in raw:
        if not isinstance(item, dict) or item.get("type") not in INDICATOR_TYPES:
            raise RuleError(f"{rule_id}: invalid indicator {item!r}")
        value = str(item.get("value", ""))
        if not value:
            raise RuleError(f"{rule_id}: indicator without value")
        if item["type"] == "bytes":
            compile_pattern(value)
        specs.append(IndicatorSpec(item["type"], value))
    return specs


def _parse_rule(raw: Any, source: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{source}: rule must be a mapping")
    missing = {"id", "name", "description", "severity", "mitre", "indicators"} - set(raw)
    rule_id = str(raw.get("id", "?"))
    if missing:
        raise RuleError(f"{rule_id}: missing fields {sorted(missing)}")
    if raw["severity"] not in SEVERITIES:
        raise RuleError(f"{rule_id}: invalid severity {raw['severity']!r}")
    mitre = raw["mitre"]
    if not isinstance(mitre, list) or not mitre or not all(_MITRE.match(str(m)) for m in mitre):
        raise RuleError(f"{rule_id}: invalid MITRE technique ids {mitre!r}")
    indicators = _indicators(raw["indicators"], rule_id, "indicators")
    condition: Condition = raw.get("condition", "any")
    needed = required_matches(condition, len(indicators))
    if not 1 <= needed <= len(indicators):
        raise RuleError(f"{rule_id}: condition {condition!r} unsatisfiable")
    return Rule(
        id=rule_id,
        name=str(raw["name"]),
        description=str(raw["description"]),
        severity=raw["severity"],
        mitre=[str(m) for m in mitre],
        condition=condition,
        indicators=indicators,
        unless=_indicators(raw.get("unless"), rule_id, "unless"),
        source=source,
    )


def load_rules(paths: Iterable[str | Path]) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in paths:
        path = Path(path)
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise RuleError(f"cannot load {path}: {exc}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
            raise RuleError(f"{path}: expected a mapping with a 'rules' list")
        for raw in doc["rules"]:
            rule = _parse_rule(raw, path.name)
            if rule.id in seen:
                raise RuleError(f"duplicate rule id {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
    return rules


# -- matching -------------------------------------------------------------------


class RuleEngine:
    """Matches rules against raw bytes plus (optionally) a parsed :class:`PEReport`."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self.rules = list(rules)
        self._patterns: dict[str, re.Pattern[bytes]] = {}
        for rule in self.rules:
            for ind in [*rule.indicators, *rule.unless]:
                if ind.type == "bytes" and ind.value not in self._patterns:
                    self._patterns[ind.value] = compile_pattern(ind.value)
                elif ind.type == "string" and ind.value not in self._patterns:
                    ascii_ = re.escape(ind.value.encode("utf-8"))
                    wide = re.escape(ind.value.encode("utf-16-le"))
                    self._patterns[ind.value] = re.compile(ascii_ + b"|" + wide)

    def scan(self, data: bytes, report: PEReport | None = None) -> list[Finding]:
        cache: dict[IndicatorSpec, list[Match]] = {}
        exported = {normalize_api(e) for e in report.exports} if report is not None else set()

        def matches(ind: IndicatorSpec) -> list[Match]:
            if ind not in cache:
                cache[ind] = self._match(ind, data, report, exported)
            return cache[ind]

        findings = []
        for rule in self.rules:
            hits = [m for ind in rule.indicators for m in matches(ind)]
            matched = sum(1 for ind in rule.indicators if matches(ind))
            if matched < required_matches(rule.condition, len(rule.indicators)):
                continue
            if any(matches(ind) for ind in rule.unless):
                continue
            findings.append(
                Finding(rule.id, rule.name, rule.severity, rule.mitre, rule.description, hits)
            )
        return findings

    def _match(
        self, ind: IndicatorSpec, data: bytes, report: PEReport | None, exported: set[str]
    ) -> list[Match]:
        if ind.type in ("import", "string") and normalize_api(ind.value) in exported:
            # The module *provides* this API (kernel32, ntdll, ...); it is not a consumer.
            return []
        if ind.type in ("bytes", "string"):
            out = []
            for m in self._patterns[ind.value].finditer(data):
                off = m.start()
                out.append(
                    Match(ind.type, ind.value, m.group().hex(" ")[:96], off, _rva(report, off))
                )
                if len(out) >= MAX_MATCHES_PER_INDICATOR:
                    break
            return out
        if report is None:
            return []
        if ind.type == "import":
            want = normalize_api(ind.value)
            return [
                Match("import", ind.value, f"{dll}!{func}")
                for dll, funcs in report.imports.items()
                for func in funcs
                if func == ind.value or normalize_api(func) == want
            ][:MAX_MATCHES_PER_INDICATOR]
        if ind.type == "export":
            return [Match("export", ind.value, e) for e in report.exports if e == ind.value][:1]
        if ind.type == "section":
            return [
                Match("section", ind.value, s.name, s.raw_offset, s.virtual_address)
                for s in report.sections
                if s.name == ind.value
            ]
        raise RuleError(f"unsupported indicator type {ind.type}")  # pragma: no cover


def _rva(report: PEReport | None, offset: int) -> int | None:
    if report is None:
        return None
    for s in report.sections:
        if s.raw_size and s.raw_offset <= offset < s.raw_offset + s.raw_size:
            return s.virtual_address + (offset - s.raw_offset)
    return None
