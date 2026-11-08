"""Triage report: one dictionary shared by the UI (WorkbenchApi) and the CLI."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from octov.core.analysis.pipeline import AnalysisContext
from octov.core.analysis.scoring import IGNORED_VERDICTS, risk_score
from octov.core.mitre import technique_name, technique_tactic

CAPABILITY_KINDS = ("rule", "indicator", "crypto_constant", "embedded_payload", "packer")
_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def build_triage(
    ctx: AnalysisContext,
    verdicts: Mapping[str, str],
    names: Mapping[int, str],
    jobs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    facts = list(ctx.facts)
    by_id = {f.id: f for f in facts}
    score = risk_score(facts, verdicts)

    capabilities = [
        f.to_dict() | {"verdict": verdicts.get(f.id)}
        for f in sorted(facts, key=lambda f: (_ORDER[f.severity], f.kind, f.source_id))
        if f.kind in CAPABILITY_KINDS
    ]

    attack: dict[str, dict[str, Any]] = {}
    for f in facts:
        if verdicts.get(f.id) in IGNORED_VERDICTS:
            continue
        for t in f.mitre:
            row = attack.setdefault(
                t,
                {
                    "technique": t,
                    "name": technique_name(t),
                    "tactic": technique_tactic(t),
                    "severity": "info",
                    "sources": [],
                },
            )
            if _ORDER[f.severity] < _ORDER[row["severity"]]:
                row["severity"] = f.severity
            if f.source_id not in row["sources"]:
                row["sources"].append(f.source_id)

    packer = ctx.results.get("packer")
    ranking = ctx.results.get("ranking", [])
    return {
        "score": {
            "score": score.score,
            "band": score.band,
            "contributions": [
                {
                    "fact_id": fid,
                    "points": pts,
                    "title": by_id[fid].title,
                    "severity": by_id[fid].severity,
                }
                for fid, pts in score.contributions
                if by_id[fid].severity != "info"
            ],
        },
        "packer": (
            {
                "packed": packer.packed,
                "confidence": packer.confidence,
                "packer": packer.packer,
                "reasons": list(packer.reasons),
            }
            if packer is not None
            else None
        ),
        "capabilities": capabilities,
        "iocs": [
            {
                "type": i.type,
                "value": i.value,
                "offsets": list(i.offsets),
                "benign_hint": i.benign_hint,
            }
            for i in ctx.results.get("iocs", [])
        ],
        "payloads": [
            {
                "offset": p.offset,
                "size": p.size,
                "kind": p.kind,
                "where": p.where,
                "sha256": p.sha256,
            }
            for p in ctx.results.get("payloads", [])
        ],
        "top_functions": [
            {
                "start": r.start,
                "name": names.get(r.start, r.name),
                "score": r.score,
                "reasons": list(r.reasons),
            }
            for r in ranking
        ],
        "attack": sorted(attack.values(), key=lambda r: (_ORDER[r["severity"]], r["technique"])),
        "orphaned_verdicts": [
            {"fact_id": fid, "verdict": v} for fid, v in verdicts.items() if fid not in by_id
        ],
        "jobs": dict(jobs or {}),
    }
