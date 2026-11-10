from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from octov.app.api import WorkbenchApi
from octov.core.config import Config
from octov.ext import ExtensionStatus
from tests.samples.builder import stack_string_pe
from tests.unit.test_triage_api import _suspicious

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FAKE = str(FIXTURES / "fake_engine.py")
URL = "http://x.example/gate.php"


def _status(ready: set[str]) -> list[ExtensionStatus]:
    return [
        ExtensionStatus(
            id=e,
            installed=e in ready,
            ready=e in ready,
            version="10.0.0" if e == "capa" else "3.2.0",
            rules_version="v10.0.0" if e == "capa" else None,
            reason_key=None if e in ready else "ext.reason.not_installed",
            install_cmd=f"python -m uv sync --extra {e}",
            setup_cmd=None,
        )
        for e in ("floss", "capa")
    ]


def _api(tmp_path: Path, config: Config | None = None, name: str = "a") -> WorkbenchApi:
    return WorkbenchApi(
        config or Config(),
        settings_path=tmp_path / f"{name}.json",
        workspace_dir=tmp_path / "ws",
        cache_dir=tmp_path / "cache",
        rules_root=tmp_path / "rules",
        sigs_root=tmp_path / "sigs",
    )


def _settled(api: WorkbenchApi, sha: str, timeout: float = 60) -> dict[str, Any]:
    end = time.monotonic() + timeout
    while True:
        jobs = api.job_status(sha)
        if not any(j["state"] in ("queued", "running") for j in jobs.values()):
            return jobs
        assert time.monotonic() < end, jobs
        time.sleep(0.05)


def test_capa_facts_reach_triage(tmp_path: Path, engines: dict[str, Any]) -> None:
    engines["ready"] = {"capa"}
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    jobs = _settled(api, sha)
    assert jobs["capa"]["state"] == "done" and not jobs["capa"]["cached"]
    assert jobs["floss"]["state"] == "unavailable"
    assert jobs["floss"]["error"] == "ext.reason.not_installed"
    kinds = {f["source_id"]: f for f in api.get_findings(sha) if f["kind"] == "capability"}
    assert "create thread" in kinds
    caps = {c["source_id"] for c in api.get_triage(sha)["capabilities"]}
    assert "create thread" in caps


def test_floss_strings_and_hidden_ioc(tmp_path: Path, engines: dict[str, Any]) -> None:
    engines["ready"] = {"floss"}
    path = tmp_path / "stack.exe"
    path.write_bytes(stack_string_pe(URL))
    api = _api(tmp_path)
    sha = api.open_sample(str(path))["sha256"]
    assert _settled(api, sha)["floss"]["state"] == "done"
    page = api.get_strings(sha, origin="stack")
    assert [i["value"] for i in page["items"]] == [URL]
    assert page["items"][0]["origin"] == "stack"
    assert api.get_strings(sha, origin="recovered")["total"] == 1
    tri = api.get_triage(sha)
    assert [c["kind"] for c in tri["capabilities"]].count("hidden_ioc") == 1
    assert URL in {i["value"] for i in api.get_iocs(sha)}


def test_cache_hit_skips_process(tmp_path: Path, engines: dict[str, Any]) -> None:
    engines["ready"] = {"capa"}
    sample = _suspicious(tmp_path)
    first = _api(tmp_path)
    sha = first.open_sample(str(sample))["sha256"]
    _settled(first, sha)
    assert engines["started"]["capa"] == 1
    second = _api(tmp_path, name="b")
    second.open_sample(str(sample))
    jobs = _settled(second, sha)
    assert jobs["capa"]["state"] == "done" and jobs["capa"]["cached"] is True
    assert engines["started"]["capa"] == 1
    assert "create thread" in {f["source_id"] for f in second.get_findings(sha)}


def test_force_rerun_replaces_cache(tmp_path: Path, engines: dict[str, Any]) -> None:
    engines["ready"] = {"capa"}
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    _settled(api, sha)
    api.run_extension(sha, "capa", force=True)
    jobs = _settled(api, sha)
    assert engines["started"]["capa"] == 2 and jobs["capa"]["cached"] is False


def test_in_memory_sample_unavailable(tmp_path: Path, engines: dict[str, Any]) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    _settled(api, sha)
    payload = api.get_triage(sha)["payloads"][0]["sha256"]
    child = api.open_payload(sha, payload)["sha256"]
    jobs = _settled(api, child)
    assert jobs["capa"] == {**jobs["capa"], "state": "unavailable", "error": "ext.reason.in_memory"}
    assert jobs["floss"]["error"] == "ext.reason.in_memory"


def test_too_large_unavailable(tmp_path: Path, engines: dict[str, Any]) -> None:
    config = Config()
    config.extensions["capa"].max_size_mb = 1
    api = _api(tmp_path, config)
    path = tmp_path / "big.exe"
    path.write_bytes(_suspicious(tmp_path).read_bytes() + b"\0" * (2 << 20))
    sha = api.open_sample(str(path))["sha256"]
    jobs = _settled(api, sha)
    assert (jobs["capa"]["state"], jobs["capa"]["error"]) == ("unavailable", "ext.reason.too_large")


def test_auto_run_off_waits_for_run(tmp_path: Path, engines: dict[str, Any]) -> None:
    engines["ready"] = {"capa"}
    api = _api(tmp_path)
    api.set_settings({"extensions_auto_run": {"capa": False, "floss": True}})
    assert api.get_settings()["extensions_auto_run"] == {
        "capa": False,
        "floss": True,
        "ghidra": True,
    }
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    assert _settled(api, sha)["capa"]["state"] == "idle"
    assert engines["started"]["capa"] == 0
    api.run_extension(sha, "capa")
    assert _settled(api, sha)["capa"]["state"] == "done"
    exts = {e["id"]: e for e in api.get_extensions()}
    assert exts["capa"]["auto_run"] is False and exts["capa"]["ready"] is True


def test_engine_failure_is_reported(tmp_path: Path, engines: dict[str, Any]) -> None:
    engines["ready"] = {"capa"}
    engines["mode"]["capa"] = ["garbage"]
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    jobs = _settled(api, sha)
    assert (jobs["capa"]["state"], jobs["capa"]["error"]) == ("failed", "unexpected engine output")
    assert not list((tmp_path / "cache").rglob("*.gz"))


def test_close_kills_running_engine(tmp_path: Path, engines: dict[str, Any]) -> None:
    engines["ready"] = {"capa"}
    engines["mode"]["capa"] = ["sleep"]
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    end = time.monotonic() + 10
    while api.job_status(sha)["capa"]["state"] != "running":
        assert time.monotonic() < end
        time.sleep(0.05)
    api.close_sample(sha)
    # the sleeping engine was killed: the next sample's capa job finishes promptly
    engines["mode"]["capa"] = ["file", str(FIXTURES / "capa" / "synthetic_injector.json")]
    other = tmp_path / "stack.exe"
    other.write_bytes(stack_string_pe(URL))
    start = time.monotonic()
    sha2 = api.open_sample(str(other))["sha256"]
    assert _settled(api, sha2, timeout=30)["capa"]["state"] == "done"
    assert time.monotonic() - start < 30


def test_concurrent_open_same_sample_one_pipeline(tmp_path: Path, engines: dict[str, Any]) -> None:
    engines["ready"] = set()
    api = _api(tmp_path)
    path = str(_suspicious(tmp_path))
    out: list[str] = []
    threads = [
        threading.Thread(target=lambda: out.append(api.open_sample(path)["sha256"]))
        for _ in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(out)) == 1
    pipelines = {id(api._get(out[0]).pipeline)}
    assert len(pipelines) == 1 and len(api.list_samples()) == 1


def test_concurrent_first_annotations_one_workspace(
    tmp_path: Path, engines: dict[str, Any]
) -> None:
    engines["ready"] = set()
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    errors: list[BaseException] = []

    def note(i: int) -> None:
        try:
            api.annotate(sha, "comment", f"c{i}", address=0x1000 + i)
        except BaseException as exc:  # surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=note, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(api.list_annotations(sha)) == 6
