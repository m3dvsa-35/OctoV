"""FLOSS adapter: command line, recovered strings, obfuscation facts."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

from octov.core.analysis.facts import Evidence, Fact
from octov.core.analysis.iocs import Ioc
from octov.core.analysis.strings import FoundString, classify
from octov.ext.runner import EngineError

SUPPORTED_MAJOR = "3"
OBFUSCATED_MIN = 5
HIDDEN_IOC_TYPES = frozenset({"url", "ipv4", "ipv6", "domain", "mutex", "wallet", "command"})
_KINDS: tuple[tuple[str, Literal["stack", "tight", "decoded"]], ...] = (
    ("stack_strings", "stack"),
    ("tight_strings", "tight"),
    ("decoded_strings", "decoded"),
)


def floss_command(path: Path, *, raw: bool, bits: int) -> list[str]:
    cmd = [sys.executable, "-m", "floss.main", "-j", "--only", "stack", "tight", "decoded"]
    if raw:
        cmd += ["--format", "sc32" if bits == 32 else "sc64"]
    return [*cmd, "--", str(path)]


def _bad() -> EngineError:
    return EngineError("bad_output", "unexpected engine output")


def parse_floss(doc: dict[str, Any], image_base: int, image_size: int) -> list[FoundString]:
    meta = doc.get("metadata")
    strings = doc.get("strings")
    version = str(meta.get("version", "")) if isinstance(meta, dict) else ""
    if version.split(".")[0] != SUPPORTED_MAJOR or not isinstance(strings, dict):
        raise _bad()

    def rva(va: Any) -> int | None:
        value = int(va) - image_base
        return value if 0 <= value < image_size else None

    out: list[FoundString] = []
    seen: set[tuple[str, str]] = set()
    try:
        for key, origin in _KINDS:
            for item in strings.get(key, []):
                value = str(item["string"])
                if not value or (value, origin) in seen:
                    continue
                seen.add((value, origin))
                if origin == "decoded":
                    function = rva(item["decoding_routine"])
                    where = rva(item["decoded_at"])
                else:
                    function = rva(item["function"])
                    where = function
                encoding: Literal["ascii", "utf16"] = (
                    "utf16" if "16" in str(item.get("encoding", "")) else "ascii"
                )
                out.append(
                    FoundString(value, encoding, -1, where, None, classify(value), origin, function)
                )
    except (KeyError, TypeError, ValueError) as exc:
        raise _bad() from exc
    return out


def merge_strings(
    static: Sequence[FoundString], recovered: Sequence[FoundString]
) -> list[FoundString]:
    """Static strings first; recovered values already present statically are dropped."""
    known = {s.value for s in static}
    out = list(static)
    for s in recovered:
        if s.value not in known:
            known.add(s.value)
            out.append(s)
    return out


def floss_facts(recovered: Sequence[FoundString], hidden_iocs: Sequence[Ioc]) -> list[Fact]:
    facts: list[Fact] = []
    if len(recovered) >= OBFUSCATED_MIN:
        functions = sorted({s.function for s in recovered if s.function is not None})
        evidence = tuple(Evidence(f"function {fn:#x}", rva=fn) for fn in functions) or (
            Evidence("recovered strings", value=str(len(recovered))),
        )
        facts.append(
            Fact(
                kind="obfuscated_strings",
                source_id="floss",
                severity="low",
                title=f"{len(recovered)} strings built or decoded at run time",
                evidence=evidence,
                explain_key="fact.obfuscated_strings",
            )
        )
    hidden = [i for i in hidden_iocs if i.type in HIDDEN_IOC_TYPES]
    if hidden:

        def producer(value: str) -> int | None:
            return next((s.function for s in recovered if value in s.value), None)

        facts.append(
            Fact(
                kind="hidden_ioc",
                source_id="floss",
                severity="medium",
                title=f"{len(hidden)} indicators only visible after deobfuscation",
                evidence=tuple(
                    Evidence(f"{i.type}: {i.value}", rva=producer(i.value), value=i.value)
                    for i in hidden
                ),
                explain_key="fact.hidden_ioc",
            )
        )
    return facts
