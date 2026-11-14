from __future__ import annotations

import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from octov.app import api as api_mod
from octov.app.api import ApiError, WorkbenchApi
from octov.core.analysis.facts import Evidence, Fact
from octov.core.config import Config
from octov.ext import ExtensionStatus, cache
from octov.ext.ghidra.manager import WorkerCommand
from octov.ext.ghidra.model import annotation_hash, cache_path
from tests.unit.test_triage_api import _suspicious

FAKE = str(Path(__file__).resolve().parents[1] / "fixtures" / "fake_ghidra_worker.py")
READY = ExtensionStatus(
    id="ghidra",
    installed=True,
    ready=True,
    version="12.2",
    rules_version="25.0.1",
    reason_key=None,
    install_cmd="python -m uv sync --extra ghidra",
    setup_cmd="octov ext setup ghidra",
)


class Env:
    def __init__(self, tmp_path: Path, mode: str = "ok") -> None:
        self.tmp = tmp_path
        self.log = tmp_path / "ops.log"
        self.mode = mode
        self.api = WorkbenchApi(
            Config(),
            settings_path=tmp_path / "ui.json",
            workspace_dir=tmp_path / "ws",
            cache_dir=tmp_path / "cache",
            ghidra_factory=lambda: WorkerCommand([sys.executable, FAKE, self.mode, str(self.log)]),
            ghidra_root=tmp_path / "projects",
        )

    def ops(self, op: str) -> int:
        return self.log.read_text(encoding="utf-8").split().count(op) if self.log.exists() else 0

    def open(self) -> str:
        sha = str(self.api.open_sample(str(_suspicious(self.tmp)))["sha256"])
        self.wait(sha)
        return sha

    def wait(self, sha: str, state: str = "done", timeout: float = 30) -> dict[str, Any]:
        end = time.monotonic() + timeout
        while True:
            job = self.api.job_status(sha).get("ghidra", {"state": None})
            if job["state"] == state:
                return job
            assert time.monotonic() < end, job
            time.sleep(0.05)

    def cached(self, sha: str, names: dict[int, str], rva: int = 0x1000) -> dict[str, Any] | None:
        return cache.load(
            cache_path(self.tmp / "cache", sha, "12.2", annotation_hash(names, {}), rva)
        )


def _until(check: Callable[[], bool], timeout: float = 20) -> None:
    end = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < end
        time.sleep(0.05)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(api_mod, "ghidra_status", lambda cfg: READY)
    e = Env(tmp_path)
    yield e
    e.api.shutdown()


def test_get_decompiled_returns_lines_marks_and_function(env: Env) -> None:
    sha = env.open()
    fact = Fact("rule", "EVA-999", "high", "Remote thread", (Evidence("call", rva=0x100D),))
    env.api._get(sha).ctx.facts.append(fact)
    out = env.api.get_decompiled(sha, 0x1007)
    assert out["entry_rva"] == 0x1000 and out["name"] == "FUN_00401000"
    assert out["octov_function"] == 0x1000
    assert out["lines"][2] == {
        "text": "  WriteProcessMemory(hProcess,param_2);",
        "rvas": [0x1007],
        "marks": [{"kind": "api", "api": "WriteProcessMemory", "family": "thread_inject"}],
    }
    assert out["lines"][3]["marks"] == [
        {"kind": "fact", "fact_id": fact.id, "severity": "high"},
        {"kind": "api", "api": "CreateRemoteThread", "family": "thread_inject"},
    ]
    assert out["lines"][0]["marks"] == []
    job = env.api.job_status(sha)["ghidra"]
    assert job["state"] == "done" and job["elapsed_s"] is not None


def test_ignored_fact_is_not_marked(env: Env) -> None:
    sha = env.open()
    fact = Fact("rule", "EVA-999", "high", "Remote thread", (Evidence("call", rva=0x100D),))
    env.api._get(sha).ctx.facts.append(fact)
    env.api.set_verdict(sha, fact.id, "false_positive")
    marks = env.api.get_decompiled(sha, 0x1000)["lines"][3]["marks"]
    assert [m["kind"] for m in marks] == ["api"]


def test_cache_hit_skips_worker(env: Env) -> None:
    sha = env.open()
    _until(lambda: env.cached(sha, {}) is not None)  # the top function is decompiled ahead
    before = env.ops("decompile")
    first = env.api.get_decompiled(sha, 0x1000)
    inside = env.api.get_decompiled(sha, 0x100D)  # an address on one of its lines
    assert first["cached"] and inside["cached"] and inside["entry_rva"] == 0x1000
    assert env.ops("decompile") == before


def test_cache_survives_a_restart_without_the_worker(env: Env) -> None:
    sha = env.open()
    _until(lambda: env.cached(sha, {}) is not None)
    env.api.close_sample(sha)
    env.mode = "slow"  # the next open is still loading when the view asks
    sha = str(env.api.open_sample(str(env.tmp / "evil.exe"))["sha256"])
    out = env.api.get_decompiled(sha, 0x1000)
    assert out["cached"] and out["lines"][2]["rvas"] == [0x1007]
    with pytest.raises(ApiError, match=r"^decomp\.analysing$"):
        env.api.get_decompiled(sha, 0x1500)  # not cached: needs the worker
    env.wait(sha)


def test_rename_changes_hash_and_redecompiles(env: Env) -> None:
    sha = env.open()
    assert env.api.get_decompiled(sha, 0x1000)["name"] == "FUN_00401000"
    ann = env.api.annotate(sha, "name", "inject_main", address=0x1000)
    out = env.api.get_decompiled(sha, 0x1000)
    assert out["name"] == "inject_main" and not out["cached"]
    assert "inject_main" in out["lines"][0]["text"]
    assert env.api.get_decompiled(sha, 0x1000)["cached"]
    env.api.delete_annotation(sha, ann["id"])  # undo: the first text is still cached
    before = env.ops("decompile")
    back = env.api.get_decompiled(sha, 0x1000)
    assert back["name"] == "FUN_00401000" and back["cached"]
    assert env.ops("decompile") == before


def test_comment_changes_hash(env: Env) -> None:
    sha = env.open()
    env.api.get_decompiled(sha, 0x1000)
    before = env.ops("decompile")
    env.api.annotate(sha, "comment", "writes the payload", address=0x1007)
    assert not env.api.get_decompiled(sha, 0x1000)["cached"]
    assert env.ops("decompile") == before + 1
    env.api.annotate(sha, "bookmark", "", address=0x1007)  # does not change pseudo-C
    assert env.api.get_decompiled(sha, 0x1000)["cached"]


def test_stale_annotation_result_is_not_cached_as_current(env: Env) -> None:
    sha = env.open()
    _until(lambda: env.cached(sha, {}) is not None)
    env.api.annotate(sha, "name", "first", address=0x1000)
    manager = env.api._ghidra
    real = manager.decompile
    calls: list[dict[int, str]] = []

    def racing(sha_: str, rva: int, names: Any, comments: Any) -> dict[str, Any]:
        calls.append(dict(names))
        reply = real(sha_, rva, names, comments)
        if len(calls) == 1:  # the analyst renames again while the first answer is on its way
            for a in env.api.list_annotations(sha):
                env.api.delete_annotation(sha, a["id"])
            env.api.annotate(sha, "name", "second", address=0x1000)
        return reply

    manager.decompile = racing  # type: ignore[method-assign]
    out = env.api.get_decompiled(sha, 0x1000)
    assert out["name"] == "second"
    assert calls == [{0x1000: "first"}, {0x1000: "second"}]
    stale, current = env.cached(sha, {0x1000: "first"}), env.cached(sha, {0x1000: "second"})
    assert stale is not None and stale["name"] == "first"
    assert current is not None and current["name"] == "second"


def test_address_outside_any_function(env: Env) -> None:
    sha = env.open()
    with pytest.raises(ApiError, match=r"^decomp\.no_function$"):
        env.api.get_decompiled(sha, 0x9999)
    assert env.api.job_status(sha)["ghidra"]["state"] == "done"


def test_raw_sample_pe_only(env: Env) -> None:
    blob = env.tmp / "blob.bin"
    blob.write_bytes(b"\x90" * 64 + b"\xc3")
    sha = env.api.open_sample(str(blob), raw=True)["sha256"]
    job = env.api.job_status(sha)["ghidra"]
    assert job["state"] == "unavailable" and job["error"] == "ext.reason.pe_only"
    with pytest.raises(ApiError, match=r"^ext\.reason\.pe_only$"):
        env.api.get_decompiled(sha, 0)
    assert env.ops("open") == 0


def test_carved_payload_is_decompilable(env: Env) -> None:
    sha = env.open()
    payload = next(p for p in env.api.list_payloads(sha) if p["kind"] == "pe")
    child = env.api.open_payload(sha, payload["sha256"])["sha256"]
    env.wait(child)
    assert env.ops("open") == 2  # the parent and the in-memory child
    assert env.api.get_decompiled(child, 0x1000)["entry_rva"] == 0x1000
    assert (env.tmp / "projects" / child).is_dir()


def test_close_sample_closes_worker(env: Env) -> None:
    sha = env.open()
    worker = env.api._ghidra.worker(sha)
    assert worker is not None and worker.alive()
    env.api.close_sample(sha)
    assert not worker.alive() and env.api._ghidra.worker(sha) is None


def test_shutdown_stops_workers(env: Env) -> None:
    sha = env.open()
    worker = env.api._ghidra.worker(sha)
    assert worker is not None
    env.api.shutdown()
    assert not worker.alive()


def test_top_functions_predecompiled(env: Env) -> None:
    sha = env.open()
    _until(lambda: env.cached(sha, {}) is not None)
    doc = env.cached(sha, {})
    assert doc is not None and doc["entry_rva"] == 0x1000 and len(doc["lines"]) == 6


def test_auto_run_off_waits_for_the_analyst(env: Env) -> None:
    auto = env.api.get_settings()["extensions_auto_run"]
    assert auto["ghidra"] is True
    env.api.set_settings({"extensions_auto_run": {**auto, "ghidra": False}})
    sha = str(env.api.open_sample(str(_suspicious(env.tmp)))["sha256"])
    assert env.api.job_status(sha)["ghidra"]["state"] == "idle"
    with pytest.raises(ApiError, match=r"^decomp\.not_ready$"):
        env.api.get_decompiled(sha, 0x1000)
    env.api.run_extension(sha, "ghidra")
    env.wait(sha)
    assert env.api.get_decompiled(sha, 0x1000)["entry_rva"] == 0x1000


def test_force_rerun_discards_the_project(env: Env) -> None:
    sha = env.open()
    assert env.ops("open") == 1
    marker = env.tmp / "projects" / sha / "analyst-must-not-see-this"
    marker.write_bytes(b"x")
    env.api.run_extension(sha, "ghidra", force=True)
    _until(lambda: env.ops("open") == 2)
    env.wait(sha)
    assert not marker.exists()
    assert env.api.get_decompiled(sha, 0x1000)["entry_rva"] == 0x1000


def test_worker_crash_is_reported_and_can_be_rerun(env: Env) -> None:
    env.mode = "crash_on_decompile"
    sha = str(env.api.open_sample(str(_suspicious(env.tmp)))["sha256"])
    job = env.wait(sha, "failed")  # the ahead-of-time decompile already hit the crash
    assert "worker exited with 3" in job["error"]
    with pytest.raises(ApiError, match=r"^decomp\.not_ready$"):
        env.api.get_decompiled(sha, 0x1000)
    env.mode = "ok"
    env.api.run_extension(sha, "ghidra")
    env.wait(sha)
    assert env.api.get_decompiled(sha, 0x1000)["entry_rva"] == 0x1000


def test_extensions_list_includes_ghidra(env: Env) -> None:
    exts = {e["id"]: e for e in env.api.get_extensions()}
    assert list(exts) == ["floss", "capa", "ghidra", "library"]
    assert exts["ghidra"]["ready"] and exts["ghidra"]["version"] == "12.2"
    assert exts["ghidra"]["auto_run"] is True
    assert exts["ghidra"]["setup_cmd"] == "octov ext setup ghidra"


def test_not_installed_is_unavailable(tmp_path: Path) -> None:
    api = WorkbenchApi(
        Config(), settings_path=tmp_path / "ui.json", workspace_dir=tmp_path / "ws"
    )  # conftest: no engines on this machine
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    job = api.job_status(sha)["ghidra"]
    assert job["state"] == "unavailable" and job["error"] == "ext.reason.not_installed"
    with pytest.raises(ApiError, match=r"^ext\.reason\.not_installed$"):
        api.get_decompiled(sha, 0x1000)
    assert not (tmp_path / "projects").exists()


def test_old_settings_file_gets_ghidra_default(tmp_path: Path) -> None:
    settings = tmp_path / "ui.json"
    settings.write_text(
        '{"language": "az", "extensions_auto_run": {"capa": false, "floss": true}}',
        encoding="utf-8",
    )
    api = WorkbenchApi(Config(), settings_path=settings, workspace_dir=tmp_path / "ws")
    assert api.get_settings()["extensions_auto_run"] == {
        "capa": False,
        "floss": True,
        "ghidra": True,
        "library": True,
    }
