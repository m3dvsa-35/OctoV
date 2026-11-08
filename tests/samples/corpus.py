"""Synthetic detection corpus: build a benign PE that carries a rule's *artifacts*.

The generated files contain the byte patterns / strings / import names a rule
looks for, laid out as inert data. They are never meant to run; they exist so
the test suite can measure rule detection without real malware.
"""

from __future__ import annotations

from octov.core.static.rules import Rule, required_matches
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

_SEPARATOR = b"\x00" * 16


def concrete_bytes(pattern: str) -> bytes:
    """Instantiate a hex pattern, replacing wildcard nibbles with 0."""
    return bytes(int(tok.replace("?", "0"), 16) for tok in pattern.split())


def sample_for_rule(rule: Rule, *, below_threshold: bool = False) -> bytes:
    needed = required_matches(rule.condition, len(rule.indicators))
    count = needed - 1 if below_threshold else needed
    chosen = rule.indicators[:count]

    blob = bytearray(_SEPARATOR)
    imports: list[str] = []
    sections = [SectionSpec(".text", b"\xc3" + b"\x90" * 15, TEXT)]
    for ind in chosen:
        if ind.type == "bytes":
            blob += concrete_bytes(ind.value) + _SEPARATOR
        elif ind.type == "string":
            blob += ind.value.encode() + _SEPARATOR
        elif ind.type == "import":
            imports.append(ind.value + ("W" if ind.value[-1].islower() else ""))
        elif ind.type == "section":
            sections.append(SectionSpec(ind.value, b"\x00" * 16, DATA))
    sections.append(SectionSpec(".data", bytes(blob), DATA))
    # Always import something benign so `import`-free rules still get a normal PE.
    return build_pe(PESpec(sections=sections, imports={"kernel32.dll": ["ExitProcess", *imports]}))
