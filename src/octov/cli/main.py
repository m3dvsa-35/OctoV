"""Headless OctoV CLI.

    octov analyze sample.exe [--json] [--session case.octov]
                             [--yara out.yar] [--sigma out.yml] [--rules extra.yaml ...]

``triage`` and ``compare`` arrive in later milestones.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from octov import __version__
from octov.core.export.sigma_gen import generate_sigma
from octov.core.export.yara_gen import generate_yara
from octov.core.session.session import Session, SessionError
from octov.core.static.analysis import StaticAnalysis, analyze, default_rules
from octov.core.static.pe_parser import PEParseError
from octov.core.static.rules import RuleError, load_rules

EXIT_OK = 0
EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="octov", description="OctoV defensive binary analysis")
    parser.add_argument("--version", action="version", version=f"octov {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    cmd = sub.add_parser("analyze", help="static PE analysis (local, no upload)")
    cmd.add_argument("file", type=Path)
    cmd.add_argument("--json", action="store_true", help="print the full report as JSON")
    cmd.add_argument("--session", type=Path, help="store the report in a .octov session")
    cmd.add_argument("--yara", type=Path, help="write a generated YARA rule to this file")
    cmd.add_argument("--sigma", type=Path, help="write a generated Sigma rule to this file")
    cmd.add_argument("--rules", type=Path, action="append", help="extra rule catalog (repeatable)")
    return parser


def _summary(a: StaticAnalysis) -> str:
    r = a.report
    lines = [
        f"{r.path}",
        f"  sha256   {r.hashes.sha256}",
        f"  imphash  {r.hashes.imphash or '-'}",
        f"  type     {r.machine} {'DLL' if r.is_dll else 'EXE'} {r.subsystem}",
        f"  entropy  {r.entropy:.3f}   sections {len(r.sections)}   imports {r.import_count}",
        f"  indicators ({len(r.indicators)}):",
    ]
    for ind in r.indicators:
        mitre = ",".join(ind.mitre) or "-"
        lines.append(f"    [{ind.severity:<6}] {ind.id:<30} {mitre:<20} {ind.description}")
    lines.append(f"  technique findings ({len(a.findings)}):")
    for f in a.findings:
        mitre = ",".join(f.mitre)
        where = next((m for m in f.matches if m.rva is not None or m.offset is not None), None)
        loc = ""
        if where is not None:
            loc = f" @ rva {where.rva:#x}" if where.rva is not None else f" @ off {where.offset:#x}"
        lines.append(f"    [{f.severity:<6}] {f.rule_id:<8} {mitre:<20} {f.name}{loc}")
    return "\n".join(lines)


def _analyze(args: argparse.Namespace) -> int:
    try:
        rules = list(default_rules())
        if args.rules:
            rules += load_rules(args.rules)
        result = analyze(args.file, rules)
    except (PEParseError, RuleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.session is not None:
        try:
            opener = Session.open if args.session.exists() else Session.create
            with opener(args.session) as session:
                session.add_sample(result)
        except SessionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    try:
        if args.yara is not None:
            args.yara.write_text(generate_yara(result.report, result.findings), encoding="utf-8")
        if args.sigma is not None:
            args.sigma.write_text(generate_sigma(result.report, result.findings), encoding="utf-8")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
    else:
        print(_summary(result))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    return EXIT_ERROR  # pragma: no cover - argparse enforces choices


if __name__ == "__main__":
    raise SystemExit(main())
