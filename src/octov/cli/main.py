"""Headless OctoV CLI.

    octov analyze sample.exe [--json] [--session case.octov] [--config config.yaml]
                             [--raw [--bits 32|64]]
                             [--yara out.yar] [--sigma out.yml] [--rules extra.yaml ...]

Rule catalogs come from ``rules.paths`` in the config (``config.yaml`` in the
current directory is used when present) plus any ``--rules`` files; rule IDs
must be unique across all of them.

``triage`` and ``compare`` arrive in later milestones.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from octov import __version__
from octov.core.config import ConfigError, load_config
from octov.core.export.sigma_gen import generate_sigma
from octov.core.export.yara_gen import generate_yara
from octov.core.session.session import Session, SessionError
from octov.core.static.analysis import (
    RawAnalysis,
    StaticAnalysis,
    analyze,
    analyze_raw,
    rule_set,
)
from octov.core.static.pe_parser import PEParseError
from octov.core.static.rules import Finding, RuleError

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
    cmd.add_argument("--config", type=Path, help="config file (default: ./config.yaml if present)")
    cmd.add_argument("--yara", type=Path, help="write a generated YARA rule to this file")
    cmd.add_argument("--sigma", type=Path, help="write a generated Sigma rule to this file")
    cmd.add_argument("--rules", type=Path, action="append", help="extra rule catalog (repeatable)")
    cmd.add_argument(
        "--raw", action="store_true", help="treat the file as a raw code blob (e.g. shellcode)"
    )
    cmd.add_argument(
        "--bits", type=int, choices=(32, 64), default=64, help="architecture for --raw (default 64)"
    )

    serve = sub.add_parser(
        "serve", help="serve the web UI in a browser (loopback, token protected)"
    )
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument(
        "--config", type=Path, help="config file (default: ./config.yaml if present)"
    )
    return parser


def _serve(args: argparse.Namespace) -> int:
    from octov.app.api import WorkbenchApi
    from octov.app.desktop import BUILD_HINT, DIST
    from octov.app.devserver import make_server

    if not (DIST / "index.html").is_file():
        print(BUILD_HINT, file=sys.stderr)
        return EXIT_ERROR
    try:
        config_path = args.config
        if config_path is None and Path("config.yaml").is_file():
            config_path = Path("config.yaml")
        api = WorkbenchApi(load_config(config_path))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    server, token = make_server(api, DIST, port=args.port)
    port = server.server_address[1]
    print(f"OctoV UI: http://127.0.0.1:{port}/?token={token}  (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return EXIT_OK


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
    lines += _findings_lines(a.findings)
    return "\n".join(lines)


def _raw_summary(a: RawAnalysis) -> str:
    s = a.sample
    lines = [
        f"{s.path}",
        f"  sha256   {s.hashes.sha256}",
        f"  type     raw x{'64' if s.bits == 64 else '86'} blob, {s.size:,} bytes",
        f"  entropy  {s.entropy:.3f}",
    ]
    lines += _findings_lines(a.findings)
    return "\n".join(lines)


def _findings_lines(findings: list[Finding]) -> list[str]:
    lines = [f"  technique findings ({len(findings)}):"]
    for f in findings:
        mitre = ",".join(f.mitre)
        where = next((m for m in f.matches if m.rva is not None or m.offset is not None), None)
        loc = ""
        if where is not None:
            loc = f" @ rva {where.rva:#x}" if where.rva is not None else f" @ off {where.offset:#x}"
        lines.append(f"    [{f.severity:<6}] {f.rule_id:<8} {mitre:<20} {f.name}{loc}")
    return lines


def _analyze(args: argparse.Namespace) -> int:
    try:
        config_path = args.config
        if config_path is None and Path("config.yaml").is_file():
            config_path = Path("config.yaml")
        config = load_config(config_path)
        rules = rule_set([*config.rules.paths, *(args.rules or [])])
        if args.raw and args.sigma is not None:
            print(
                "error: Sigma rules need a PE (process/image-load hashes); unavailable with --raw",
                file=sys.stderr,
            )
            return EXIT_ERROR
        result: StaticAnalysis | RawAnalysis = (
            analyze_raw(args.file, rules, bits=args.bits) if args.raw else analyze(args.file, rules)
        )
    except PEParseError as exc:
        hint = "" if args.raw else " (use --raw to analyse a shellcode/code blob)"
        print(f"error: {exc}{hint}", file=sys.stderr)
        return EXIT_ERROR
    except (RuleError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    sample = result.sample if isinstance(result, RawAnalysis) else result.report

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
            args.yara.write_text(generate_yara(sample, result.findings), encoding="utf-8")
        if args.sigma is not None and isinstance(result, StaticAnalysis):
            args.sigma.write_text(generate_sigma(result.report, result.findings), encoding="utf-8")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
    else:
        print(_raw_summary(result) if isinstance(result, RawAnalysis) else _summary(result))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "serve":
        return _serve(args)
    return EXIT_ERROR  # pragma: no cover - argparse enforces choices


if __name__ == "__main__":
    raise SystemExit(main())
