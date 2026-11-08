"""Generate a Sigma hunting rule for an analysed sample.

The rule matches Sysmon-style ``Hashes`` fields (process creation for EXEs,
image load for DLLs) and carries the ATT&CK techniques observed statically as
tags, so hunts can be pivoted by technique.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import yaml

from octov.core.static.pe_parser import Indicator, PEReport
from octov.core.static.rules import Finding

_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/m3dvsa-35/OctoV")
_LEVELS = {"info": "informational", "low": "low", "medium": "medium", "high": "high"}
_ORDER = ["info", "low", "medium", "high"]


def _level(findings: list[Finding], indicators: Sequence[Indicator]) -> str:
    severities = [f.severity for f in findings] + [i.severity for i in indicators]
    worst = max(severities, key=_ORDER.index, default="low")
    return _LEVELS[max(worst, "low", key=_ORDER.index)]


def generate_sigma(
    report: PEReport, findings: list[Finding], indicators: Sequence[Indicator] | None = None
) -> str:
    """``indicators`` defaults to all of ``report.indicators`` (pass the kept ones to filter)."""
    if indicators is None:
        indicators = report.indicators
    name = report.path.replace("\\", "/").rsplit("/", 1)[-1] if report.path else None
    label = name or report.hashes.sha256[:12]
    techniques = sorted(
        {t for f in findings for t in f.mitre} | {t for i in indicators for t in i.mitre}
    )
    hashes = [f"SHA256={report.hashes.sha256.upper()}", f"MD5={report.hashes.md5.upper()}"]
    if report.hashes.imphash:
        hashes.append(f"IMPHASH={report.hashes.imphash.upper()}")

    techniques_text = ", ".join(techniques) if techniques else "none"
    doc: dict[str, Any] = {
        "title": f"OctoV - execution of analysed sample {label}",
        "id": str(uuid.uuid5(_NAMESPACE, report.hashes.sha256)),
        "status": "experimental",
        "description": (
            f"Detects {'loading' if report.is_dll else 'execution'} of a binary analysed with "
            f"OctoV (SHA-256 {report.hashes.sha256}). Static techniques: {techniques_text}."
        ),
        "author": "OctoV",
        "date": datetime.now(tz=UTC).date(),
        "tags": [f"attack.{t.lower()}" for t in techniques],
        "logsource": {
            "category": "image_load" if report.is_dll else "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection": {"Hashes|contains": hashes},
            "condition": "selection",
        },
        "falsepositives": ["Unrelated software sharing the same import table (IMPHASH match)"],
        "level": _level(findings, indicators),
    }
    if not doc["tags"]:
        del doc["tags"]
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
