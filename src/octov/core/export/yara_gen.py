"""Generate a YARA detection rule from static findings.

Strategy: collect the indicators actually observed for the findings (byte
patterns, strings, imports, sections). The rule fires when at least two thirds
of the observed strings/patterns *and* two thirds of the observed imports are
present (`pe.imports` returns an integer, so imports are summed), plus every
observed section name. This tolerates small variants while staying anchored to
evidence. Without findings, an exact-hash rule is emitted instead.
"""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime

from octov.core.static.pe_parser import PEReport
from octov.core.static.rules import Finding

_IDENT = re.compile(r"[^A-Za-z0-9_]+")


def sanitize_rule_name(name: str) -> str:
    ident = _IDENT.sub("_", name).strip("_")[:120] or "OctoV_rule"
    return f"r_{ident}" if ident[0].isdigit() else ident


def _escape(text: str) -> str:
    out = []
    for ch in text:
        if ch in ('"', "\\"):
            out.append("\\" + ch)
        elif 0x20 <= ord(ch) < 0x7F:
            out.append(ch)
        else:
            out.extend(f"\\x{b:02x}" for b in ch.encode("utf-8"))
    return "".join(out)


def _meta(report: PEReport, findings: list[Finding]) -> list[str]:
    techniques = sorted({t for f in findings for t in f.mitre})
    lines = [
        'author = "OctoV"',
        f'date = "{datetime.now(tz=UTC).date().isoformat()}"',
        f'description = "{_escape(_description(report, findings))}"',
        f'sha256 = "{report.hashes.sha256}"',
    ]
    if report.hashes.imphash:
        lines.append(f'imphash = "{report.hashes.imphash}"')
    if techniques:
        lines.append(f'mitre_attack = "{", ".join(techniques)}"')
    if findings:
        lines.append(f'octov_rules = "{", ".join(f.rule_id for f in findings)}"')
    return lines


def _description(report: PEReport, findings: list[Finding]) -> str:
    if not findings:
        return "Exact-hash match for an analysed sample (no technique findings)."
    names = "; ".join(f.name for f in findings[:5])
    more = f" (+{len(findings) - 5} more)" if len(findings) > 5 else ""
    return f"Static technique evidence: {names}{more}"


def _two_thirds(n: int) -> int:
    return max(1, math.ceil(n * 2 / 3))


def generate_yara(report: PEReport, findings: list[Finding], rule_name: str | None = None) -> str:
    name = sanitize_rule_name(rule_name or f"OctoV_{report.hashes.sha256[:12]}")
    strings: dict[tuple[str, str], str] = {}
    imports: dict[str, None] = {}
    sections: dict[str, None] = {}
    for finding in findings:
        for m in finding.matches:
            if m.type in ("bytes", "string"):
                strings.setdefault((m.type, m.value), f"$s{len(strings)}")
            elif m.type == "import" and "!" in m.detail:
                dll, func = m.detail.split("!", 1)
                imports[f'pe.imports("{_escape(dll)}", "{_escape(func)}")'] = None
            elif m.type == "section":
                sections[f'for any s in pe.sections : (s.name == "{_escape(m.value)}")'] = None

    clauses: list[str] = []
    if strings:
        clauses.append(f"{_two_thirds(len(strings))} of ($s*)")
    if imports:
        clauses.append(f"({' + '.join(imports)}) >= {_two_thirds(len(imports))}")
    clauses += [f"({expr})" for expr in sections]
    lines = ['import "pe"', 'import "hash"', "", f"rule {name}", "{", "    meta:"]
    lines += [f"        {m}" for m in _meta(report, findings)]

    if strings:
        lines.append("    strings:")
        for (kind, value), ident in strings.items():
            if kind == "bytes":
                lines.append(f"        {ident} = {{ {value} }}")
            else:
                lines.append(f'        {ident} = "{_escape(value)}" ascii wide')

    lines.append("    condition:")
    if clauses:
        joined = " and\n        ".join(clauses)
        lines.append(f"        uint16(0) == 0x5A4D and\n        {joined}")
    else:
        lines.append(
            f"        filesize == {report.size} and "
            f'hash.sha256(0, filesize) == "{report.hashes.sha256}"'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"
