"""Every fact the analyzers can emit must be explained in English and Azerbaijani."""

from __future__ import annotations

from octov.core.i18n.az import STRINGS as AZ
from octov.core.i18n.en import STRINGS as EN

FACT_KINDS = (
    "rule",
    "indicator",
    "crypto_constant",
    "embedded_payload",
    "packer",
    "ioc",
    "obfuscated_strings",
    "hidden_ioc",
)
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
    from octov.ext.capa import CAPA_NAMESPACES

    keys = [f"fact.{k}.{part}" for k in FACT_KINDS for part in ("explain", "next")]
    keys += [f"ind.{i}.explain" for i in INDICATOR_IDS]
    keys += ["fact.capability.next"]
    keys += [f"capa.ns.{ns}.explain" for ns in CAPA_NAMESPACES]
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


def test_capa_namespaces_cover_the_rule_set() -> None:
    from octov.ext.capa import CAPA_NAMESPACES

    assert set(CAPA_NAMESPACES) >= {
        "anti-analysis",
        "collection",
        "communication",
        "data-manipulation",
        "host-interaction",
        "persistence",
        "other",
    }


def test_capa_facts_use_known_namespace_keys() -> None:
    from octov.ext.capa import CAPA_NAMESPACES, CapaMatch, capa_facts

    for ns in ("persistence/registry/run", "", "brand-new/thing"):
        fact = capa_facts([CapaMatch("r", ns, (), (), (0x1000,))], None)[0]
        assert fact.explain_key is not None
        assert fact.explain_key.removeprefix("capa.ns.") in CAPA_NAMESPACES


def test_extension_ui_strings_exist() -> None:
    keys = [
        "ext.reason.not_installed",
        "ext.reason.no_rules",
        "ext.reason.in_memory",
        "ext.reason.too_large",
        "ext.capa.adds",
        "ext.floss.adds",
        "ext.install",
        "ext.setup",
        "ext.run",
        "ext.rerun",
        "ext.auto_run",
        "ext.cached",
        "ext.queued",
        "ext.idle",
        "strings.origin",
        "strings.origin.static",
        "strings.origin.stack",
        "strings.origin.tight",
        "strings.origin.decoded",
        "strings.obfuscated",
        "triage.capa_group",
        "triage.job.idle",
    ]
    assert [k for k in keys if k not in EN or k not in AZ] == []
