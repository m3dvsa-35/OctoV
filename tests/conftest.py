"""Shared pytest configuration."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_machine_engines(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests never pick up capa/FLOSS/Ghidra installed on the developer machine.

    Tests that need engines replace ``octov.app.api.extension_status`` themselves
    (see tests/unit/test_ext_api.py); integration tests call the runner directly.
    """
    from octov.app import api
    from octov.ext import ENGINES, ExtensionStatus

    monkeypatch.setattr(
        api,
        "extension_status",
        lambda root: [
            ExtensionStatus(e, False, False, None, None, "ext.reason.not_installed", "", None)
            for e in ENGINES
        ],
    )
    monkeypatch.setattr(
        api,
        "library_status",
        lambda root: ExtensionStatus(
            "library", False, False, None, None, "ext.reason.not_installed", "", None
        ),
    )
    monkeypatch.setattr(
        api,
        "library_status",
        lambda root: ExtensionStatus(
            "library", False, False, None, None, "ext.reason.not_installed", "", None
        ),
    )
    monkeypatch.setattr(
        api,
        "ghidra_status",
        lambda cfg: ExtensionStatus(
            "ghidra", False, False, None, None, "ext.reason.not_installed", "", None
        ),
    )
