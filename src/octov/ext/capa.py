"""capa adapter: command line, result-document parser, rule matches -> facts."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from octov.core.analysis.facts import Evidence, Fact
from octov.core.static.cfg import FunctionIndex
from octov.core.static.pe_parser import Severity
from octov.ext.runner import EngineError

SUPPORTED_MAJOR = "10"

# Behaviours that rarely appear in benign software. Everything else is ``info``:
# a benign DLL matches 20-40 capa rules. Tuned only via the System32 calibration.
MEDIUM_PREFIXES: tuple[str, ...] = (
    "host-interaction/process/inject",
    "persistence/",
    "collection/keylog",
    "anti-analysis/anti-vm",
    "anti-analysis/obfuscation",
    "impact/",
    "communication/c2",
)


@dataclass(frozen=True)
class CapaMatch:
    rule: str
    namespace: str
    attack: tuple[str, ...]
    mbc: tuple[str, ...]
    rvas: tuple[int, ...]


def capa_command(path: Path, rules_dir: Path, sigs_dir: Path, *, raw: bool, bits: int) -> list[str]:
    cmd = [sys.executable, "-m", "capa.main", "-j", "-q", "-r", str(rules_dir), "-s", str(sigs_dir)]
    if raw:
        cmd += ["-f", "sc32" if bits == 32 else "sc64"]
    return [*cmd, str(path)]


def capa_severity(namespace: str) -> Severity:
    return "medium" if namespace.startswith(MEDIUM_PREFIXES) else "info"


def _bad() -> EngineError:
    return EngineError("bad_output", "unexpected engine output")


def parse_capa(doc: dict[str, Any], image_base: int, image_size: int) -> list[CapaMatch]:
    """Top-level (non-``lib``) rule matches with image-relative addresses."""
    meta = doc.get("meta")
    rules = doc.get("rules")
    version = str(meta.get("version", "")) if isinstance(meta, dict) else ""
    if version.split(".")[0] != SUPPORTED_MAJOR or not isinstance(rules, dict):
        raise _bad()
    out = []
    for name, rule in rules.items():
        try:
            rmeta = rule["meta"]
            if rmeta.get("lib"):
                continue
            rvas: set[int] = set()
            for address, _result in rule.get("matches", []):
                if address.get("type") != "absolute":
                    continue
                rva = int(address["value"]) - image_base
                if 0 <= rva < image_size:
                    rvas.add(rva)
            out.append(
                CapaMatch(
                    rule=str(name),
                    namespace=str(rmeta.get("namespace") or ""),
                    attack=tuple(str(a["id"]) for a in rmeta.get("attack", []) if a.get("id")),
                    mbc=tuple(str(m["id"]) for m in rmeta.get("mbc", []) if m.get("id")),
                    rvas=tuple(sorted(rvas)),
                )
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _bad() from exc
    return out


def capa_facts(matches: Sequence[CapaMatch], index: FunctionIndex | None) -> list[Fact]:
    facts = []
    for m in matches:
        evidence: list[Evidence] = []
        functions: list[int] = []
        for rva in m.rvas:
            fn = index.lookup(rva) if index is not None else None
            if fn is not None and fn.start not in functions:
                functions.append(fn.start)
        evidence += [Evidence(f"function {start:#x}", rva=start) for start in functions]
        evidence += [Evidence("match", rva=rva) for rva in m.rvas if rva not in functions]
        if not evidence:  # file-scope match: anchor at the file start, like header facts
            evidence = [Evidence("file", offset=0, rva=0, value=m.rule)]
        facts.append(
            Fact(
                kind="capability",
                source_id=m.rule,
                severity=capa_severity(m.namespace),
                title=m.rule,
                evidence=tuple(evidence),
                mitre=m.attack,
                tags=(*m.mbc, m.namespace) if m.namespace else m.mbc,
                explain_key=f"capa.ns.{m.namespace.split('/')[0] or 'other'}",
            )
        )
    return facts
