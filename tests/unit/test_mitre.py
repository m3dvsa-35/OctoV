"""Every technique ID emitted by rules or indicators must have a local name."""

from __future__ import annotations

from pathlib import Path

import yaml

from octov.core.mitre import TECHNIQUES, technique_name

RULES = Path(__file__).resolve().parents[2] / "rules"


def test_every_catalog_technique_has_a_name() -> None:
    ids = {
        t
        for name in ("evasion_patterns.yaml", "pic_patterns.yaml")
        for rule in yaml.safe_load((RULES / name).read_text(encoding="utf-8"))["rules"]
        for t in rule["mitre"]
    }
    ids |= {"T1027", "T1027.002", "T1027.007", "T1106", "T1055", "T1622", "T1070.006"}
    assert ids <= set(TECHNIQUES)
    assert technique_name("T1055.012") == "Process Hollowing"
    assert technique_name("T9999") == "T9999"
