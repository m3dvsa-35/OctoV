"""Headless OctoV CLI.

    octov analyze sample.exe [--json] [--session case.octov]

``triage`` and ``compare`` arrive in later milestones.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from octov import __version__
from octov.core.session.session import Session, SessionError
from octov.core.static.pe_parser import PEParseError, PEReport, parse_pe

EXIT_OK = 0
EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="octov", description="OctoV defensive binary analysis")
    parser.add_argument("--version", action="version", version=f"octov {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="static PE analysis (local, no upload)")
    analyze.add_argument("file", type=Path)
    analyze.add_argument("--json", action="store_true", help="print the full report as JSON")
    analyze.add_argument("--session", type=Path, help="store the report in a .octov session")
    return parser


def _summary(r: PEReport) -> str:
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
    return "\n".join(lines)


def _analyze(args: argparse.Namespace) -> int:
    try:
        report = parse_pe(args.file)
    except PEParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.session is not None:
        try:
            opener = Session.open if args.session.exists() else Session.create
            with opener(args.session) as session:
                session.add_sample(report)
        except SessionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    else:
        print(_summary(report))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    return EXIT_ERROR  # pragma: no cover - argparse enforces choices


if __name__ == "__main__":
    raise SystemExit(main())
