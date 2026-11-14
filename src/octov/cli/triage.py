"""`octov triage`: the same triage report as the UI, as text, Markdown or JSON."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from octov.core.config import ConfigError, load_config
from octov.ext import ENGINES

WAIT_SECONDS = 300


def add_parser(sub: Any) -> None:
    cmd = sub.add_parser("triage", help="assisted triage report (score, IOCs, capabilities)")
    cmd.add_argument("file", type=Path)
    fmt = cmd.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="full report as JSON")
    fmt.add_argument("--md", action="store_true", help="report as Markdown")
    cmd.add_argument("--iocs", type=Path, help="also write the IOC list as CSV")
    cmd.add_argument("--raw", action="store_true", help="treat the file as a raw code blob")
    cmd.add_argument("--bits", type=int, choices=(32, 64), default=64)
    cmd.add_argument("--no-ext", action="store_true", help="skip the capa / FLOSS engines")
    cmd.add_argument("--config", type=Path, help="config file (default: ./config.yaml if present)")


_MBC = re.compile(r"^[A-Z]\d{4}")


def _capa_groups(r: dict[str, Any]) -> list[tuple[str, list[dict[str, Any]]]]:
    """capa capability facts grouped by top-level namespace, largest group first."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for c in r["capabilities"]:
        if c["kind"] != "capability":
            continue
        ns = next((t for t in reversed(c["tags"]) if not _MBC.match(t)), "other")
        groups.setdefault(ns.split("/")[0], []).append(c)
    return sorted(groups.items(), key=lambda g: (-len(g[1]), g[0]))


def _text(name: str, r: dict[str, Any]) -> str:
    s = r["score"]
    lines = [f"{name}", f"  Risk {s['score']}/100 ({s['band']})"]
    for c in s["contributions"][:10]:
        if c["points"]:
            lines.append(f"    +{c['points']:<3} {c['title']}")
    if r["packer"] and r["packer"]["packed"]:
        lines.append(
            f"  Packed: {r['packer']['packer'] or 'unknown'} ({'; '.join(r['packer']['reasons'])})"
        )
    own = [c for c in r["capabilities"] if c["kind"] != "capability"]
    lines.append(f"  Capabilities ({len(own)}):")
    for c in own:
        lines.append(f"    [{c['severity']:<6}] {c['source_id']:<28} {c['title']}")
    groups = _capa_groups(r)
    if groups:
        lines.append("  Capabilities (capa):")
        for ns, rows in groups:
            lines.append(f"    {ns} ({len(rows)}): " + "; ".join(c["source_id"] for c in rows))
    if r.get("recovered_strings"):
        lines.append(f"  Recovered strings (FLOSS): {r['recovered_strings']}")
    lines.append(f"  IOCs ({len(r['iocs'])}):")
    for i in r["iocs"]:
        hint = f"  ({i['benign_hint']})" if i["benign_hint"] else ""
        lines.append(f"    {i['type']:<10} {i['value']}{hint}")
    if r["payloads"]:
        lines.append(f"  Embedded payloads ({len(r['payloads'])}):")
        for p in r["payloads"]:
            lines.append(f"    {p['kind']:<12} {p['size']:>9,} B  @ {p['offset']:#x}  {p['where']}")
    if r["top_functions"]:
        lines.append("  Most suspicious functions:")
        for f in r["top_functions"][:10]:
            lines.append(
                f"    {f['start']:#010x} {f['name']:<28} {f['score']:>3}  "
                + "; ".join(f["reasons"][:3])
            )
    return "\n".join(lines)


def _markdown(name: str, r: dict[str, Any]) -> str:
    s = r["score"]
    out = [f"# Triage: {name}", "", f"**Risk:** {s['score']}/100 ({s['band']})", ""]
    if r["packer"] and r["packer"]["packed"]:
        out += [
            f"**Packed:** {r['packer']['packer'] or 'unknown'} - "
            + "; ".join(r["packer"]["reasons"]),
            "",
        ]
    out += ["## Capabilities", "", "| Severity | ID | Finding | ATT&CK |", "|---|---|---|---|"]
    out += [
        f"| {c['severity']} | {c['source_id']} | {c['title']} | {', '.join(c['mitre'])} |"
        for c in r["capabilities"]
        if c["kind"] != "capability"
    ]
    groups = _capa_groups(r)
    if groups:
        out += ["", "## Capabilities (capa)"]
        for ns, rows in groups:
            out += ["", f"### {ns} ({len(rows)})", ""]
            out += [
                f"- {c['source_id']} ({c['severity']})"
                + (f" - {', '.join(c['mitre'])}" if c["mitre"] else "")
                for c in rows
            ]
    if r.get("recovered_strings"):
        out += ["", f"**Recovered strings (FLOSS):** {r['recovered_strings']}"]
    out += ["", "## IOCs", "", "| Type | Value | Note |", "|---|---|---|"]
    out += [f"| {i['type']} | `{i['value']}` | {i['benign_hint'] or ''} |" for i in r["iocs"]]
    if r["top_functions"]:
        out += ["", "## Most suspicious functions", ""]
        out += [
            f"- `{f['start']:#x}` **{f['name']}** ({f['score']}): {'; '.join(f['reasons'])}"
            for f in r["top_functions"][:10]
        ]
    return "\n".join(out) + "\n"


def run(args: argparse.Namespace) -> int:
    from octov.app.api import ApiError, WorkbenchApi

    try:
        config_path = args.config
        if config_path is None and Path("config.yaml").is_file():
            config_path = Path("config.yaml")
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        api = WorkbenchApi(
            config, settings_path=Path(tmp) / "ui.json", workspace_dir=Path(tmp) / "ws"
        )
        # the decompiler adds nothing to a triage report: never start it from the CLI
        auto = {"ghidra": False, "library": False} | (
            {e: False for e in ENGINES} if args.no_ext else {}
        )
        api.set_settings({"extensions_auto_run": auto})
        try:
            sha = api.open_sample(str(args.file), raw=args.raw, bits=args.bits)["sha256"]
        except ApiError as exc:
            hint = "" if args.raw else " (use --raw for shellcode / code blobs)"
            print(f"error: {exc}{hint}", file=sys.stderr)
            return 2
        engine_wait = max(e.timeout_s for e in config.extensions.values()) + 60
        deadline = time.monotonic() + max(WAIT_SECONDS, engine_wait)
        while any(j["state"] in ("queued", "running") for j in api.job_status(sha).values()):
            if time.monotonic() > deadline:
                break
            time.sleep(0.05)
        report = api.get_triage(sha)
        report["iocs"] = api.get_iocs(sha)  # the UI payload is capped, the CLI lists all
        report["recovered_strings"] = api.get_strings(sha, limit=0, origin="recovered")["total"]
        if args.iocs is not None:
            args.iocs.write_text(api.export_iocs(sha, "csv"), encoding="utf-8")
    name = args.file.name
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    elif args.md:
        print(_markdown(name, report), end="")
    else:
        print(_text(name, report))
    return 0
