from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from octov.core.analysis.naming import API_FAMILIES
from octov.core.apidoc import API_DOC, api_doc_key, api_doc_keys
from octov.core.i18n.az import STRINGS as AZ
from octov.core.i18n.en import STRINGS as EN
from octov.core.static import pe_parser
from octov.core.static.pe_parser import normalize_api

RULES = Path(__file__).resolve().parents[2] / "rules"


def _rule_imports(node: Any) -> set[str]:
    if isinstance(node, dict):
        found = {str(node["value"])} if node.get("type") == "import" and "value" in node else set()
        return found.union(*(_rule_imports(v) for v in node.values()))
    if isinstance(node, list):
        return set().union(*(_rule_imports(v) for v in node))
    return set()


def _documented(api: str) -> bool:
    key = api_doc_key(api)
    return key is not None and bool(EN.get(key)) and bool(AZ.get(key))


def test_every_family_api_documented() -> None:
    missing = [api for apis in API_FAMILIES.values() for api in apis if not _documented(api)]
    assert missing == []


def test_rule_imports_documented() -> None:
    names: set[str] = set()
    for path in sorted(RULES.glob("*.yaml")):
        names |= _rule_imports(yaml.safe_load(path.read_text(encoding="utf-8")))
    assert len(names) > 20  # the walker really found the import conditions
    assert sorted(n for n in names if not _documented(n)) == []


def test_indicator_apis_documented() -> None:
    names = (
        pe_parser.INJECTION_APIS
        | pe_parser.ANTI_DEBUG_APIS
        | pe_parser._RESOLVER_LOAD
        | pe_parser._RESOLVER_GET
    )
    assert sorted(n for n in names if not _documented(n)) == []


def test_az_translated() -> None:
    keys = api_doc_keys()
    assert len(keys) == len(API_DOC) > 100
    for key in keys:
        en, az = EN[key], AZ[key]
        assert az != en, key
        for text in (en, az):
            assert "\n" not in text and 20 <= len(text) <= 170, key
            assert ";" in text, key  # what it does; why malware uses it
            assert "{" not in text, key  # never mistaken for a format placeholder


def test_api_strings_only_for_documented_apis() -> None:
    assert {k for k in EN if k.startswith("api.")} == set(api_doc_keys())
    assert {k for k in AZ if k.startswith("api.")} == set(api_doc_keys())
    assert all(normalize_api(name) == name for name in API_DOC)  # keys are normalised names


def test_api_doc_key_ignores_ansi_wide_suffix() -> None:
    assert api_doc_key("CreateFileW") == "api.CreateFile"
    assert api_doc_key("RegSetValueExA") == "api.RegSetValueEx"
    assert api_doc_key("send") == "api.send"
    assert api_doc_key("GetTickCount") is None


@pytest.mark.parametrize(
    "key",
    [
        "decomp.help.title",
        "decomp.help.body",
        "decomp.no_function",
        "decomp.analysing",
        "decomp.not_ready",
        "decomp.timeout",
        "decomp.failed",
        "decomp.mark.fact",
        "decomp.mark.api",
        "ext.reason.no_ghidra",
        "ext.reason.ghidra_version",
        "ext.reason.no_jdk",
        "ext.reason.pe_only",
        "ext.ghidra.adds",
        "ui.pseudo_c",
    ],
)
def test_decompiler_strings_in_both_languages(key: str) -> None:
    assert EN.get(key) and AZ.get(key) and EN[key] != AZ[key]
