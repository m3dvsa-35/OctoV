"""`octov ext`: status of the optional engines and their one-time setup."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from octov.core.config import ConfigError, load_config
from octov.ext import DEFAULT_RULES_ROOT, DEFAULT_SIGS_ROOT, extension_status
from octov.ext.ghidra.discover import ghidra_status
from octov.ext.library import library_status

EXIT_SETUP_FAILED = 2


def add_parser(sub: Any) -> None:
    ext = sub.add_parser("ext", help="optional engines (capa, FLOSS): status and setup")
    ext_sub = ext.add_subparsers(dest="ext_command", required=True)
    status = ext_sub.add_parser("status", help="show installed engines and capa rules")
    setup = ext_sub.add_parser("setup", help="install the capa rule set (one-time download)")
    setup.add_argument("engine", choices=("capa", "ghidra", "library"))
    setup.add_argument("--from-zip", type=Path, help="install from a local rules archive")
    setup.add_argument(
        "--allow-unpinned", action="store_true", help="accept a rules archive with another hash"
    )
    setup.add_argument("--sigs-from", type=Path, help="copy the signature files from this folder")
    setup.add_argument("--no-sigs", action="store_true", help="skip the signature files")
    for p in (status, setup):
        p.add_argument("--rules-root", type=Path, default=None, help=argparse.SUPPRESS)
        p.add_argument("--home-root", type=Path, default=None, help=argparse.SUPPRESS)
        p.add_argument("--sigs-root", type=Path, default=None, help=argparse.SUPPRESS)


def _rules_root(args: argparse.Namespace) -> Path:
    root: Path = args.rules_root or DEFAULT_RULES_ROOT
    return root.expanduser()


def run(args: argparse.Namespace) -> int:
    if args.ext_command == "status":
        for st in extension_status(_rules_root(args)):
            if st.ready:
                state = f"ready (version {st.version}"
                state += f", rules {st.rules_version})" if st.rules_version else ")"
            elif not st.installed:
                state = f"not installed: {st.install_cmd}"
            else:
                state = f"installed {st.version}, rules missing: {st.setup_cmd}"
            print(f"{st.id:<6} {state}")
        print(_ghidra_line(args))
        print(_library_line(args))
        return 0
    if args.engine == "ghidra":
        return _setup_ghidra(args)
    if args.engine == "library":
        return _setup_library(args)

    from octov.ext.capa_rules import RulesError, install_rules, install_sigs

    try:
        target = install_rules(
            _rules_root(args), zip_path=args.from_zip, allow_unpinned=args.allow_unpinned
        )
        print(f"capa rules installed in {target}")
        if not args.no_sigs:
            sigs_root: Path = (args.sigs_root or DEFAULT_SIGS_ROOT).expanduser()
            sigs = install_sigs(sigs_root, from_dir=args.sigs_from)
            print(f"capa signatures installed in {sigs}")
    except (RulesError, OSError) as exc:
        print(f"capa rules setup failed: {exc}", file=sys.stderr)
        return EXIT_SETUP_FAILED
    return 0


def _sigs_root(args: argparse.Namespace) -> Path:
    root: Path = args.sigs_root or DEFAULT_SIGS_ROOT
    return root.expanduser()


def _library_line(args: argparse.Namespace) -> str:
    st = library_status(_sigs_root(args))
    if st.ready:
        return f"library ready (signatures {st.rules_version})"
    if not st.installed:
        return f"library not installed: {st.install_cmd}"
    return f"library signatures missing: {st.setup_cmd}"


def _setup_library(args: argparse.Namespace) -> int:
    """Only the pinned signature files (library recognition works without capa)."""
    from octov.ext.capa_rules import RulesError, install_sigs

    try:
        sigs = install_sigs(_sigs_root(args), from_dir=args.sigs_from)
    except (RulesError, OSError) as exc:
        print(f"library signatures setup failed: {exc}", file=sys.stderr)
        return EXIT_SETUP_FAILED
    print(f"library signatures installed in {sigs}")
    return 0


def _home_root(args: argparse.Namespace) -> Path:
    root: Path = args.home_root or Path.home() / ".octov"
    return root


def _ghidra_line(args: argparse.Namespace) -> str:
    try:
        cfg = load_config(Path("config.yaml") if Path("config.yaml").is_file() else None)
    except ConfigError:
        cfg = load_config(None)
    st = ghidra_status(cfg.ghidra, home_root=_home_root(args))
    if st.ready:
        return f"ghidra ready (Ghidra {st.version}, JDK {st.rules_version})"
    if not st.installed:
        return f"ghidra not installed: {st.install_cmd}"
    if st.reason_key == "ext.reason.no_jdk":
        return "ghidra needs a JDK >= 21 (set extensions.ghidra.java_home)"
    if st.reason_key == "ext.reason.ghidra_version":
        return f"ghidra {st.version} is not supported (need 12.x): {st.setup_cmd}"
    return f"ghidra missing: {st.setup_cmd}"


def _setup_ghidra(args: argparse.Namespace) -> int:
    from octov.ext.archive import RulesError
    from octov.ext.ghidra import setup

    if args.from_zip is None:
        mib = setup.GHIDRA_SIZE // (1 << 20)
        source = "github.com/NationalSecurityAgency/ghidra"
        print(f"downloading Ghidra {setup.GHIDRA_VERSION} ({mib} MiB) from {source}")
    try:
        target = setup.install_ghidra(_home_root(args), zip_path=args.from_zip)
    except (RulesError, OSError) as exc:
        print(f"ghidra setup failed: {exc}", file=sys.stderr)
        return EXIT_SETUP_FAILED
    print(f"Ghidra {setup.GHIDRA_VERSION} installed in {target}")
    return 0
