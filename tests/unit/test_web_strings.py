"""Every UI string key used by the web frontend must exist in both languages."""

from __future__ import annotations

import re
from pathlib import Path

from octov.core.i18n.az import STRINGS as AZ
from octov.core.i18n.en import STRINGS as EN

WEB_SRC = Path(__file__).resolve().parents[2] / "web" / "src"
# t("key") / t(`sev.${x}`) -> static keys only; dynamic severity keys are expanded below.
KEY = re.compile(r"""\bt\(\s*["']([a-z_]+(?:\.[a-z_]+)+)["']""")


def _used_keys() -> set[str]:
    keys: set[str] = set()
    for path in WEB_SRC.rglob("*.tsx"):
        keys |= set(KEY.findall(path.read_text(encoding="utf-8")))
    for path in WEB_SRC.rglob("*.ts"):
        keys |= set(KEY.findall(path.read_text(encoding="utf-8")))
    keys |= {f"sev.{s}" for s in ("high", "medium", "low", "info")}
    return keys


def test_frontend_keys_exist_in_english_and_azerbaijani() -> None:
    used = _used_keys()
    assert len(used) > 40
    assert sorted(used - set(EN)) == []
    assert sorted(used - set(AZ)) == []
