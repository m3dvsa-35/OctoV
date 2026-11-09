"""Opening a large sample must stay interactive: fast analyzers finish within the budget."""

from __future__ import annotations

import time
from pathlib import Path

from octov.app.api import WorkbenchApi
from octov.core.config import Config
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

FAST_BUDGET_S = 3.0
SIZE = 5 * 1024 * 1024


def _large_pe() -> bytes:
    # Realistic mix: code-like bytes, many short ASCII/UTF-16 strings and zero padding.
    code = (bytes.fromhex("4883EC28E8000000004883C428C3") + b"\x90" * 2) * (SIZE // 32)
    chunk = b"".join(
        b"config_value_%05d\x00" % i + f"Software\\Vendor\\Key{i}\0".encode("utf-16-le")
        for i in range(40_000)
    )
    data = (chunk + b"\x00" * SIZE)[: SIZE // 2]
    return build_pe(
        PESpec(
            sections=[
                SectionSpec(".text", code[: SIZE // 2], TEXT),
                SectionSpec(".data", data, DATA),
            ],
            imports={"kernel32.dll": ["ExitProcess", "CreateFileW"]},
        )
    )


def test_fast_analyzers_on_5mb_pe_within_budget(tmp_path: Path) -> None:
    sample = tmp_path / "large.exe"
    sample.write_bytes(_large_pe())
    assert sample.stat().st_size >= SIZE
    api = WorkbenchApi(Config(), settings_path=tmp_path / "ui.json", workspace_dir=tmp_path / "ws")
    start = time.perf_counter()
    sha = api.open_sample(str(sample))["sha256"]
    elapsed = time.perf_counter() - start
    assert api.get_triage(sha)["score"]["band"] in ("low", "medium", "high")
    assert elapsed < FAST_BUDGET_S, f"open_sample (fast analyzers) took {elapsed:.2f}s"
