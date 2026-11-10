"""Which Windows APIs have a one-line explanation (texts: ``i18n/en_api.py`` / ``az_api.py``)."""

from __future__ import annotations

from octov.core.i18n.en_api import API_STRINGS
from octov.core.static.pe_parser import normalize_api

API_DOC: dict[str, str] = {key.removeprefix("api."): key for key in API_STRINGS}


def api_doc_keys() -> list[str]:
    return sorted(API_DOC.values())


def api_doc_key(name: str) -> str | None:
    """i18n key for an API name, with or without its ANSI/Unicode suffix."""
    return API_DOC.get(name) or API_DOC.get(normalize_api(name))
