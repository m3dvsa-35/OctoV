"""`octov ext`: status of the optional engines and one-time capa rules setup."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from octov.ext import DEFAULT_RULES_ROOT, DEFAULT_SIGS_ROOT, extension_status

EXIT_SETUP_FAILED = 2


def add_parser(sub: Any) -> None:
    ext = sub.add_parser("ext", help="optional engines (capa, FLOSS): status and setup")
    ext_sub = ext.add_subparsers(dest="ext_command", required=True)
    status = ext_sub.add_parser("status", help="show installed engines and capa rules")
    setup = ext_sub.add_parser("setup", help="install the capa rule set (one-time download)")
    setup.add_argument("engine", choices=("capa",))
    setup.add_argument("--from-zip", type=Path, help="install from a local rules archive")
    setup.add_argument(
        "--allow-unpinned", action="store_true", help="accept a rules archive with another hash"
    )
    setup.add_argument("--sigs-from", type=Path, help="copy the signature files from this folder")
    setup.add_argument("--no-sigs", action="store_true", help="skip the signature files")
    for p in (status, setup):
        p.add_argument("--rules-root", type=Path, default=None, help=argparse.SUPPRESS)
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
        return 0

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
