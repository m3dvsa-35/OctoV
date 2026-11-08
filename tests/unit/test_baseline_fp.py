r"""False-positive baseline: signed Windows system binaries must not raise high-severity alerts.

Scans a deterministic slice of C:\Windows\System32 (every Nth file) so it stays
fast in CI. The full sweep is documented in CLAUDE.md; run it with
OCTOV_FULL_BASELINE=1.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from octov.app.api import ApiError, WorkbenchApi
from octov.core.config import Config
from octov.core.static.analysis import analyze
from octov.core.static.pe_parser import PEParseError

SYSTEM32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
FULL = bool(os.environ.get("OCTOV_FULL_BASELINE"))
STRIDE = 1 if FULL else 25
# The full pipeline (strings, xrefs, ranking) is ~1 s per file: sample fewer in CI.
PIPELINE_STRIDE = 1 if FULL else 80
JOB_TIMEOUT = 120.0


def _baseline_files(stride: int = STRIDE) -> list[Path]:
    if not SYSTEM32.is_dir():
        return []
    files = sorted(p for p in SYSTEM32.iterdir() if p.suffix.lower() in (".exe", ".dll"))
    return files[::stride]


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


def _full_triage(api: WorkbenchApi, path: Path) -> dict[str, object] | None:
    """Open ``path``, wait for the slow analyzers, return the triage report (None = skipped)."""
    try:
        sha = api.open_sample(str(path))["sha256"]
    except (ApiError, PermissionError):
        return None
    deadline = time.monotonic() + JOB_TIMEOUT
    while any(j["state"] in ("queued", "running") for j in api.job_status(sha).values()):
        assert time.monotonic() < deadline, f"{path.name}: analyzers did not finish"
        time.sleep(0.02)
    report = api.get_triage(sha)
    api.close_sample(sha)
    return report


@pytest.mark.skipif(not SYSTEM32.is_dir(), reason="requires a Windows System32 directory")
def test_system32_full_pipeline_baseline(tmp_path: Path) -> None:
    """Every fact kind (crypto, payloads, packer, IOCs...) stays quiet on system files."""
    api = WorkbenchApi(Config(), settings_path=tmp_path / "ui.json", workspace_dir=tmp_path / "ws")
    offenders: list[str] = []
    bands: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    raised: list[str] = []
    for path in _baseline_files(PIPELINE_STRIDE):
        report = _full_triage(api, path)
        if report is None:
            continue
        caps = report["capabilities"]
        score = report["score"]
        assert isinstance(caps, list) and isinstance(score, dict)
        high = [c["source_id"] for c in caps if c["severity"] == "high"]
        if high:
            offenders.append(f"{path.name}: {', '.join(high)}")
        bands[score["band"]] += 1
        if score["band"] != "low":
            raised.append(f"{path.name}: {score['score']}")
    scanned = sum(bands.values())
    print(f"\npipeline baseline: {scanned} files, bands {bands}, not low: {raised}")
    assert scanned >= 40
    assert offenders == [], "\n".join(offenders)
    assert bands["low"] / scanned >= 0.95, f"{bands}; not low: {raised}"
