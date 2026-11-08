from __future__ import annotations

from octov.core.i18n import LANGUAGES, ai_language_instruction, tr
from octov.core.i18n.az import STRINGS as AZ
from octov.core.i18n.en import STRINGS as EN


def test_az_and_en_define_the_same_keys() -> None:
    assert set(AZ) == set(EN)
    assert set(LANGUAGES) == {"en", "az"}


def test_translates_known_key() -> None:
    assert tr("menu.file", "az") == "Fayl"
    assert tr("menu.file", "en") == "File"


def test_unknown_language_falls_back_to_english() -> None:
    assert tr("menu.file", "de") == "File"


def test_unknown_key_returns_key() -> None:
    assert tr("no.such.key", "az") == "no.such.key"


def test_format_arguments() -> None:
    assert "evil.exe" in tr("status.loaded", "az", name="evil.exe")


def test_ai_instruction_requests_azerbaijani_for_az() -> None:
    assert "Azerbaijani" in ai_language_instruction("az")
    assert ai_language_instruction("en") == ""
