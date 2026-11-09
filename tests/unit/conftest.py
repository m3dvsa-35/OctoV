"""Fixtures shared by the extension (capa / FLOSS) tests."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from octov.app import api as api_mod
from octov.ext import capa as capa_ext
from octov.ext import floss as floss_ext
from tests.unit.test_ext_api import FAKE, FIXTURES, _status


@pytest.fixture
def engines(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """Fake engines printing recorded output; counts how often each one started."""
    started = {"capa": 0, "floss": 0}
    state: dict[str, Any] = {"ready": {"capa", "floss"}, "started": started, "mode": {}}

    def capa_cmd(path: Path, rules: Path, sigs: Path, *, raw: bool, bits: int) -> list[str]:
        started["capa"] += 1
        return [
            sys.executable,
            FAKE,
            *state["mode"].get(
                "capa", ["file", str(FIXTURES / "capa" / "synthetic_injector.json")]
            ),
        ]

    def floss_cmd(path: Path, *, raw: bool, bits: int) -> list[str]:
        started["floss"] += 1
        return [
            sys.executable,
            FAKE,
            *state["mode"].get("floss", ["file", str(FIXTURES / "floss" / "synthetic_stack.json")]),
        ]

    monkeypatch.setattr(capa_ext, "capa_command", capa_cmd)
    monkeypatch.setattr(floss_ext, "floss_command", floss_cmd)
    monkeypatch.setattr(api_mod, "extension_status", lambda root: _status(state["ready"]))
    (tmp_path / "rules" / "v10.0.0").mkdir(parents=True)
    (tmp_path / "rules" / "v10.0.0" / "r.yml").write_text("x", encoding="utf-8")
    return state
