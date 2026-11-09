"""False-positive baseline: signed Windows system binaries must not raise high-severity alerts.

Scans a deterministic slice of C:\\Windows\\System32 (every Nth file) so it stays
fast in CI. The full sweep (4370 files, 0 high hits at the time of writing) is
documented in CLAUDE.md; run it with OCTOV_FULL_BASELINE=1.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from octov.core.static.analysis import analyze
from octov.core.static.pe_parser import PEParseError

SYSTEM32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
STRIDE = 1 if os.environ.get("OCTOV_FULL_BASELINE") else 25


def _baseline_files() -> list[Path]:
    if not SYSTEM32.is_dir():
        return []
    files = sorted(p for p in SYSTEM32.iterdir() if p.suffix.lower() in (".exe", ".dll"))
    return files[::STRIDE]


@pytest.mark.skipif(not SYSTEM32.is_dir(), reason="requires a Windows System32 directory")
def test_system32_baseline_has_no_high_severity_hits() -> None:
    offenders: list[str] = []
    scanned = 0
    for path in _baseline_files():
        try:
            result = analyze(path)
        except (PEParseError, PermissionError):
            continue
        scanned += 1
        high = [i.id for i in result.report.indicators if i.severity == "high"]
        high += [f.rule_id for f in result.findings if f.severity == "high"]
        if high:
            offenders.append(f"{path.name}: {', '.join(high)}")
    assert scanned >= 50
    assert offenders == [], "\n".join(offenders)
