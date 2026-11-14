from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from octov.app import api as api_mod
from octov.app.api import WorkbenchApi
from octov.core.analysis import analyzers
from octov.core.config import Config
from octov.core.static.pe_parser import parse_pe
from octov.ext import ExtensionStatus
from tests.samples.builder import library_like_pe
from tests.unit.test_ext_api import FAKE, _api, _settled

READY = ExtensionStatus(
    "library", True, True, "1", "v1.0.0", None, "python -m uv sync", "octov ext setup library"
)


@pytest.fixture
def library(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """A fake worker naming every function except the entry point ``lib_<rva>``."""
    state: dict[str, Any] = {"started": 0, "mode": None, "starts": None}

    def command(sample: Path, sigs: Path, starts_file: Path) -> list[str]:
        state["started"] += 1
        starts = json.loads(starts_file.read_text(encoding="utf-8"))
        state["starts"] = starts
        state["starts_file"] = starts_file
        if state["mode"] is not None:
            return [sys.executable, FAKE, *state["mode"]]
        entry = parse_pe(sample.read_bytes()).entry_point
        doc = {
            "engine": "library",
            "version": 1,
            "sets": [{"file": "test.pat", "signatures": len(starts)}],
            "candidates": [
                {"rva": s, "set": "test.pat", "names": [f"lib_{s:x}"], "count": 1}
                for s in starts
                if s != entry
            ],
        }
        out = tmp_path / f"library-doc-{state['started']}.json"
        out.write_text(json.dumps(doc), encoding="utf-8")
        return [sys.executable, FAKE, "file", str(out)]

    monkeypatch.setattr(api_mod.library_ext, "library_command", command)
    monkeypatch.setattr(api_mod, "library_status", lambda root: READY)
    sigs = tmp_path / "sigs" / "v1.0.0"
    sigs.mkdir(parents=True)
    (sigs / "test.pat").write_bytes(b"---\n")
    return state


def _sample(tmp_path: Path, count: int = 7) -> Path:
    path = tmp_path / f"lib{count}.exe"
    path.write_bytes(library_like_pe(count))
    return path


def _open(api: WorkbenchApi, path: Path) -> str:
    sha: str = api.open_sample(str(path))["sha256"]
    return sha


def test_library_names_reach_the_function_list(tmp_path: Path, library: dict[str, Any]) -> None:
    api = _api(tmp_path)
    sha = _open(api, _sample(tmp_path))
    jobs = _settled(api, sha)
    assert jobs["library"]["state"] == "done", jobs["library"]
    rows = api.list_functions(sha)
    assert len(library["starts"]) == len(rows) == 8
    lib = [r for r in rows if r["library"]]
    assert len(lib) == 7
    assert all(r["name"] == f"lib_{r['start']:x}" and not r["suggested"] for r in lib)
    entry = next(r for r in rows if r["is_entry"])
    assert not entry["library"]
    assert api.get_triage(sha)["library"] == {"functions": 7, "total": 8}
    assert not library["starts_file"].exists()  # the temp file is gone


def test_analyst_names_win_over_library_names(tmp_path: Path, library: dict[str, Any]) -> None:
    api = _api(tmp_path)
    sha = _open(api, _sample(tmp_path))
    _settled(api, sha)
    start = next(r["start"] for r in api.list_functions(sha) if r["library"])
    api.annotate(sha, "name", "my_decoder", address=start)
    row = next(r for r in api.list_functions(sha) if r["start"] == start)
    assert row["name"] == "my_decoder" and not row["library"]
    assert api.get_function(sha, start)["name"] == "my_decoder"


def test_library_result_is_cached(tmp_path: Path, library: dict[str, Any]) -> None:
    api = _api(tmp_path)
    path = _sample(tmp_path)
    sha = _open(api, path)
    assert _settled(api, sha)["library"]["cached"] is False
    api.close_sample(sha)
    sha = _open(api, path)
    job = _settled(api, sha)["library"]
    assert (job["state"], job["cached"]) == ("done", True)
    assert library["started"] == 1
    assert sum(r["library"] for r in api.list_functions(sha)) == 7

    api.run_extension(sha, "library", force=True)
    job = _settled(api, sha)["library"]
    assert (job["state"], job["cached"], library["started"]) == ("done", False, 2)


def test_library_unavailable_without_signatures(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = _open(api, _sample(tmp_path))
    job = _settled(api, sha)["library"]
    assert (job["state"], job["error"]) == ("unavailable", "ext.reason.not_installed")
    assert not any(r["library"] for r in api.list_functions(sha))
    ext = {e["id"]: e for e in api.get_extensions()}
    assert ext["library"]["ready"] is False and ext["library"]["auto_run"] is True


def test_library_is_idle_when_auto_run_is_off_and_runs_on_request(
    tmp_path: Path, library: dict[str, Any]
) -> None:
    api = _api(tmp_path)
    api.set_settings({"extensions_auto_run": {"library": False}})
    sha = _open(api, _sample(tmp_path))
    assert _settled(api, sha)["library"]["state"] == "idle"
    assert library["started"] == 0
    api.run_extension(sha, "library")
    assert _settled(api, sha)["library"]["state"] == "done"
    assert sum(r["library"] for r in api.list_functions(sha)) == 7


def test_raw_samples_are_pe_only(tmp_path: Path, library: dict[str, Any]) -> None:
    blob = tmp_path / "sc.bin"
    blob.write_bytes(b"\x90" * 32 + b"\xc3")
    api = _api(tmp_path)
    sha = api.open_sample(str(blob), raw=True)["sha256"]
    job = _settled(api, sha)["library"]
    assert (job["state"], job["error"]) == ("unavailable", "ext.reason.pe_only")


def test_too_large_samples_are_skipped(tmp_path: Path, library: dict[str, Any]) -> None:
    config = Config()
    config.extensions["library"].max_size_mb = 1
    path = tmp_path / "big.exe"
    path.write_bytes(library_like_pe() + b"\x00" * (1024 * 1024))
    api = _api(tmp_path, config)
    job = _settled(api, _open(api, path))["library"]
    assert (job["state"], job["error"]) == ("unavailable", "ext.reason.too_large")


def test_bad_worker_output_fails_the_job(tmp_path: Path, library: dict[str, Any]) -> None:
    library["mode"] = ["garbage"]
    api = _api(tmp_path)
    sha = _open(api, _sample(tmp_path))
    job = _settled(api, sha)["library"]
    assert job["state"] == "failed" and "unexpected engine output" in job["error"]
    assert len(api.list_functions(sha)) == 8

    library["mode"] = ["ok"]  # JSON, but not the worker's document
    api.run_extension(sha, "library", force=True)
    job = _settled(api, sha)["library"]
    assert job["state"] == "failed" and "unexpected engine output" in job["error"]
    api.close_sample(sha)
    library["mode"] = None
    sha = _open(api, _sample(tmp_path))  # nothing bad was cached
    assert _settled(api, sha)["library"]["state"] == "done"


def test_closing_the_sample_drops_the_job(tmp_path: Path, library: dict[str, Any]) -> None:
    library["mode"] = ["sleep"]
    api = _api(tmp_path)
    sha = _open(api, _sample(tmp_path))
    end = time.monotonic() + 30
    while api.job_status(sha)["library"]["state"] != "running" or library["started"] == 0:
        assert time.monotonic() < end
        time.sleep(0.02)
    api.close_sample(sha)
    library["mode"] = None
    other = _open(api, _sample(tmp_path, count=8))
    assert _settled(api, other, timeout=30)["library"]["state"] == "done"
    assert sum(r["library"] for r in api.list_functions(other)) == 8


def test_library_waits_for_functions_and_gives_up_when_they_fail(
    tmp_path: Path, library: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: Any, ctx: Any) -> None:
        raise RuntimeError("no functions today")

    monkeypatch.setattr(analyzers.Functions, "run", boom)
    api = _api(tmp_path)
    sha = _open(api, _sample(tmp_path))
    job = _settled(api, sha)["library"]
    assert (job["state"], job["error"]) == ("unavailable", "needs functions")
    assert library["started"] == 0


def test_capa_and_library_results_both_apply(
    tmp_path: Path, engines: dict[str, Any], library: dict[str, Any]
) -> None:
    engines["ready"] = {"capa"}
    api = _api(tmp_path)
    sha = _open(api, _sample(tmp_path))
    jobs = _settled(api, sha)
    assert jobs["capa"]["state"] == jobs["library"]["state"] == "done", jobs
    assert sum(r["library"] for r in api.list_functions(sha)) == 7
    assert any(c["kind"] == "capability" for c in api.get_triage(sha)["capabilities"])


def test_config_has_library_limits() -> None:
    lib = Config().extensions["library"]
    assert (lib.timeout_s, lib.max_size_mb, lib.max_memory_mb) == (120, 64, 2048)


def test_a_bad_cache_file_is_replaced_not_trusted(tmp_path: Path, library: dict[str, Any]) -> None:
    import hashlib

    from octov.ext import cache as ext_cache

    path = _sample(tmp_path)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    cached = ext_cache.cache_file(tmp_path / "cache", sha, "library", "1", "v1.0.0")
    ext_cache.store(cached, {"engine": "something else"})
    api = _api(tmp_path)
    assert _open(api, path) == sha
    job = _settled(api, sha)["library"]
    assert (job["state"], job["cached"], library["started"]) == ("done", False, 1)
    assert sum(r["library"] for r in api.list_functions(sha)) == 7
    api.close_sample(sha)
    _open(api, path)
    job = _settled(api, sha)["library"]
    assert (job["state"], job["cached"], library["started"]) == ("done", True, 1)


def test_closing_while_functions_are_discovered_then_reopening(
    tmp_path: Path, library: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    gate = threading.Event()
    real = analyzers.Functions.run

    def slow(self: Any, ctx: Any) -> None:
        assert gate.wait(30)
        real(self, ctx)

    monkeypatch.setattr(analyzers.Functions, "run", slow)
    api = _api(tmp_path)
    path = _sample(tmp_path)
    sha = _open(api, path)
    assert api.job_status(sha)["library"]["state"] == "queued"
    api.close_sample(sha)  # the first sample's job is still waiting for its functions
    assert _open(api, path) == sha
    gate.set()
    assert _settled(api, sha)["library"]["state"] == "done"
    time.sleep(1.2)  # the closed sample's waiter has woken up by now
    assert library["started"] == 1
    assert sum(r["library"] for r in api.list_functions(sha)) == 7


def test_no_functions_means_done_without_starting_the_worker(
    tmp_path: Path, library: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from octov.core.static.cfg import FunctionIndex

    def nothing(self: Any, ctx: Any) -> None:
        ctx.functions = {}
        ctx.index = FunctionIndex({})

    monkeypatch.setattr(analyzers.Functions, "run", nothing)
    api = _api(tmp_path)
    sha = _open(api, _sample(tmp_path))
    job = _settled(api, sha)["library"]
    assert (job["state"], library["started"]) == ("done", 0)
    assert api.get_triage(sha)["library"] == {"functions": 0, "total": 0}
