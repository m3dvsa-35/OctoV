"""Minimal dictionary-based i18n for the OctoV UI and AI prompts."""

from __future__ import annotations

from typing import Any

from octov.core.i18n import az, en

LANGUAGES: dict[str, dict[str, str]] = {"en": en.STRINGS, "az": az.STRINGS}
DEFAULT_LANGUAGE = "en"


def tr(key: str, lang: str = DEFAULT_LANGUAGE, **kwargs: Any) -> str:
    """Translate ``key`` into ``lang`` (falls back to English, then to the key itself)."""
    text = LANGUAGES.get(lang, en.STRINGS).get(key) or en.STRINGS.get(key, key)
    return text.format(**kwargs) if kwargs else text


def ai_language_instruction(lang: str) -> str:
    """System-prompt suffix that makes the AI assistant answer in the UI language."""
    if lang == "az":
        return (
            "Respond in Azerbaijani (Azərbaycan dili, Latin script). Keep technical "
            "identifiers, API names, offsets and MITRE ATT&CK IDs unchanged."
        )
    return ""
