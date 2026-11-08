"""Every fact the analyzers can emit must be explained in English and Azerbaijani."""

from __future__ import annotations

from octov.core.i18n.az import STRINGS as AZ
from octov.core.i18n.en import STRINGS as EN

FACT_KINDS = ("rule", "indicator", "crypto_constant", "embedded_payload", "packer", "ioc")
INDICATOR_IDS = (
    "high_entropy_section",
    "rwx_section",
    "packer_section_name",
    "virtual_size_inflated",
    "entry_point_not_executable",
    "entry_point_outside_sections",
    "no_imports",
    "dynamic_api_resolution",
    "process_injection_apis",
    "anti_debug_apis",
    "overlay_present",
    "suspicious_timestamp",
)


def _keys() -> list[str]:
    keys = [f"fact.{k}.{part}" for k in FACT_KINDS for part in ("explain", "next")]
    keys += [f"ind.{i}.explain" for i in INDICATOR_IDS]
    return keys


def test_all_explanations_exist_in_both_languages() -> None:
    missing = [k for k in _keys() if k not in EN or k not in AZ]
    assert missing == []


def test_azerbaijani_texts_are_translated() -> None:
    same = [k for k in _keys() if k in EN and k in AZ and EN[k] == AZ[k]]
    assert same == []


def test_explanations_are_substantial() -> None:
    short = [k for k in _keys() if k.endswith(".explain") and len(EN.get(k, "")) < 60]
    assert short == []


def test_every_indicator_id_from_parser_is_covered() -> None:
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[2] / "src/octov/core/static/pe_parser.py").read_text(
        encoding="utf-8"
    )
    emitted = set(re.findall(r'Indicator\(\s*"([a-z_]+)"', src))
    assert emitted <= set(INDICATOR_IDS)
