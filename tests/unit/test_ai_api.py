from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from octov.app.api import ApiError, WorkbenchApi
from octov.core.analysis.pipeline import Pipeline
from octov.core.config import Config
from tests.fixtures.fake_llm import FakeLLM
from tests.unit.test_triage_api import _suspicious

KEY = "sk-test-not-a-real-key-0123456789"
FACT = "indicator:process_injection_apis:0x3048"
REPLY = {
    "summary": "Injects code into another process.",
    "assessment": "malicious",
    "confidence": "high",
    "story": [
        {"text": "Writes and starts a remote thread.", "functions": ["0x1000"], "findings": [FACT]}
    ],
    "points": [
        {
            "title": "Process injection",
            "why": "Two APIs together.",
            "severity": "high",
            "findings": [FACT, "rule:MADE-UP:0x0"],
            "functions": ["0x1000"],
        }
    ],
    "links": [],
}


@pytest.fixture
def llm() -> Iterator[FakeLLM]:
    server = FakeLLM(json.dumps(REPLY))
    yield server
    server.close()


def _api(tmp_path: Path, llm: FakeLLM | None, **ai: Any) -> WorkbenchApi:
    config = Config()
    if llm is not None:
        config.ai.base_url = llm.base_url
        config.ai.model = "fake-model"
    for key, value in ai.items():
        setattr(config.ai, key, value)
    return WorkbenchApi(
        config,
        settings_path=tmp_path / "ui.json",
        workspace_dir=tmp_path / "ws",
        cache_dir=tmp_path / "cache",
    )


def _open(api: WorkbenchApi, tmp_path: Path) -> str:
    sha = str(api.open_sample(str(_suspicious(tmp_path)))["sha256"])
    assert api._get(sha).pipeline.wait_slow(30)
    return sha


def _wait(api: WorkbenchApi, sha: str, timeout: float = 20) -> dict[str, Any]:
    end = time.monotonic() + timeout
    while True:
        job: dict[str, Any] = api.job_status(sha).get("ai", {"state": "idle"})
        if job["state"] in ("done", "failed"):
            return job
        assert time.monotonic() < end, job
        time.sleep(0.02)


def _run(api: WorkbenchApi, sha: str, force: bool = False) -> dict[str, Any]:
    api.ai_analyse(sha, api.ai_preview(sha)["hash"], force)
    return _wait(api, sha)


def test_status_lists_endpoints_without_the_key(tmp_path: Path, llm: FakeLLM) -> None:
    local = _api(tmp_path, llm).ai_status()
    assert local["configured"] is True
    assert local["endpoints"] == [
        {"host": "127.0.0.1", "model": "fake-model", "local": True, "has_key": False}
    ]
    remote = _api(
        tmp_path, None, api_key=KEY, base_url="https://ai.example/v1", model="m"
    ).ai_status()
    assert remote["endpoints"] == [
        {"host": "ai.example", "model": "m", "local": False, "has_key": True}
    ]
    assert KEY not in json.dumps(remote)
    assert _api(tmp_path, None).ai_status() == {"configured": False, "endpoints": []}  # no key


def test_preview_is_what_gets_sent(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    preview = api.ai_preview(sha)
    assert preview["host"] == "127.0.0.1" and preview["model"] == "fake-model" and preview["local"]
    assert preview["chars"] == len(preview["text"]) and len(preview["hash"]) == 16
    doc = json.loads(preview["text"])
    assert doc["sample"]["name"] == "evil.exe" and doc["functions"][0]["addr"] == "0x1000"
    assert FACT in [f["id"] for f in doc["findings"]]
    assert "CreateRemoteThread" in [a["name"] for a in doc["functions"][0]["apis"]]
    assert "http://x.example/gate.php" in doc["functions"][0]["strings"]
    assert doc["functions"][0]["code_kind"] == "asm" and "call" in doc["functions"][0]["code"]
    assert llm.requests == []  # looking is not sending
    assert _run(api, sha)["state"] == "done"
    (req,) = llm.posts
    assert req["body"]["messages"][1] == {"role": "user", "content": preview["text"]}
    assert "untrusted" in req["body"]["messages"][0]["content"]
    assert str(tmp_path) not in json.dumps(req["body"])  # no local paths leave the machine


def test_nothing_is_sent_without_the_current_hash(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    for bad in ("", "0" * 16):
        with pytest.raises(ApiError, match=r"^ai\.preview_changed$"):
            api.ai_analyse(sha, bad)
    seen = api.ai_preview(sha)["hash"]
    api.annotate(sha, "name", "inject_main", address=0x1000)  # the evidence changed after looking
    with pytest.raises(ApiError, match=r"^ai\.preview_changed$"):
        api.ai_analyse(sha, seen)
    assert llm.requests == [] and "ai" not in api.job_status(sha)
    assert _run(api, sha)["state"] == "done"
    assert "inject_main" in llm.posts[0]["body"]["messages"][1]["content"]


def test_report_is_validated_and_cached(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    assert api.get_ai_report(sha) is None
    job = _run(api, sha)
    assert job["state"] == "done" and not job["cached"] and job["elapsed_s"] is not None
    report = api.get_ai_report(sha)
    assert report is not None and report["assessment"] == "malicious"
    assert report["points"][0]["findings"] == [FACT] and report["dropped"] == 1  # invented id gone
    assert report["story"][0]["functions"] == [0x1000]
    assert report["model"] == "fake-model" and report["host"] == "127.0.0.1" and report["local"]
    assert report["bundle_hash"] == api.ai_preview(sha)["hash"]
    again = _run(api, sha)
    assert again["state"] == "done" and again["cached"] and len(llm.posts) == 1
    assert _run(api, sha, force=True)["cached"] is False and len(llm.posts) == 2
    # a fresh app instance finds the report without asking again
    other = _api(tmp_path, llm)
    assert other.get_ai_report(_open(other, tmp_path)) == api.get_ai_report(sha)


def test_failure_ends_failed_with_a_key_free_reason(tmp_path: Path, llm: FakeLLM) -> None:
    llm.mode = "401"
    api = _api(tmp_path, llm, api_key=KEY)
    sha = _open(api, tmp_path)
    job = _run(api, sha)
    assert job["state"] == "failed" and job["error"] == "ai.auth"
    assert api.get_ai_report(sha) is None
    dump = json.dumps([api.job_status(sha), api.ai_status(), api.ai_preview(sha)])
    assert KEY not in dump and "Bearer" not in dump
    assert llm.posts[0]["authorization"] is None  # a local server never gets the remote key
    llm.mode = "ok"
    assert _run(api, sha)["state"] == "done"  # asking again works


@pytest.mark.parametrize(
    ("mode", "reply"), [("garbage", ""), ("ok", "I would rather not."), ("ok", "{}")]
)
def test_bad_reply_is_failed_not_stuck(tmp_path: Path, llm: FakeLLM, mode: str, reply: str) -> None:
    llm.mode, llm.reply = mode, reply or "x"
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    job = _run(api, sha)
    assert job["state"] == "failed" and job["error"] == "ai.bad_response"
    assert list((tmp_path / "cache").rglob("ai-*")) == []  # a bad answer is never cached


def test_no_endpoint(tmp_path: Path) -> None:
    api = _api(tmp_path, None)  # default remote endpoint, no key
    sha = _open(api, tmp_path)
    preview = api.ai_preview(sha)
    assert preview["host"] is None and preview["text"]
    with pytest.raises(ApiError, match=r"^ai\.no_endpoint$"):
        api.ai_analyse(sha, preview["hash"])
    assert api.get_ai_report(sha) is None


def test_not_ready_before_discovery(
    tmp_path: Path, llm: FakeLLM, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Pipeline, "start_slow", lambda self, ctx, on_done=None: None)
    api = _api(tmp_path, llm)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    with pytest.raises(ApiError, match=r"^analysis\.not_ready$"):
        api.ai_preview(sha)
    with pytest.raises(ApiError, match=r"^analysis\.not_ready$"):
        api.ai_analyse(sha, "0" * 16)
    assert api.get_ai_report(sha) is None and llm.requests == []


def test_raw_sample_works(tmp_path: Path, llm: FakeLLM) -> None:
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\xe8\x0b\x00\x00\x00\xc3".ljust(0x10, b"\xcc") + b"\xb8\x37\x13\x00\x00\xc3")
    llm.reply = json.dumps(REPLY | {"story": [], "points": [], "assessment": "suspicious"})
    api = _api(tmp_path, llm)
    sha = str(api.open_sample(str(blob), raw=True)["sha256"])
    assert api._get(sha).pipeline.wait_slow(30)
    doc = json.loads(api.ai_preview(sha)["text"])
    assert doc["sample"]["format"] == "raw" and doc["sample"]["entry_point"] is None
    assert _run(api, sha)["state"] == "done"
    assert api.get_ai_report(sha)["assessment"] == "suspicious"  # type: ignore[index]


def test_report_stays_and_is_marked_stale_when_evidence_changes(
    tmp_path: Path, llm: FakeLLM
) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    assert _run(api, sha)["state"] == "done"
    fresh = api.get_ai_report(sha)
    assert fresh is not None and fresh["stale"] is False
    # background engines or the analyst change the evidence: the opinion stays, labelled
    api.annotate(sha, "comment", "writes the payload", address=0x1007)
    kept = api.get_ai_report(sha)
    assert kept is not None and kept["stale"] is True
    assert kept["summary"] == fresh["summary"] and kept["bundle_hash"] == fresh["bundle_hash"]
    assert len(llm.posts) == 1  # keeping it costs no new request
    assert _run(api, sha)["state"] == "done" and len(llm.posts) == 2
    assert api.get_ai_report(sha)["stale"] is False  # type: ignore[index]


def test_a_failed_endpoint_never_falls_back_by_itself(tmp_path: Path, llm: FakeLLM) -> None:
    other = FakeLLM(json.dumps(REPLY))
    try:
        llm.mode = "429"
        api = _api(tmp_path, llm, fallback_base_url=other.base_url, fallback_model="other-model")
        sha = _open(api, tmp_path)
        preview = api.ai_preview(sha)
        assert [e["model"] for e in preview["endpoints"]] == ["fake-model", "other-model"]
        assert preview["host"] == "127.0.0.1" and preview["model"] == "fake-model"
        job = _run(api, sha)
        assert job["state"] == "failed" and job["error"] == "ai.rate_limit"
        assert len(llm.posts) == 1 and other.requests == []  # nobody confirmed that destination
    finally:
        other.close()


def test_the_analyst_chooses_the_destination(tmp_path: Path, llm: FakeLLM) -> None:
    other = FakeLLM(json.dumps(REPLY))
    try:
        api = _api(tmp_path, llm, fallback_base_url=other.base_url, fallback_model="other-model")
        sha = _open(api, tmp_path)
        preview = api.ai_preview(sha)
        api.ai_analyse(sha, preview["hash"], False, 1)
        assert _wait(api, sha)["state"] == "done"
        assert llm.requests == [] and len(other.posts) == 1
        assert other.posts[0]["body"]["model"] == "other-model"
        assert api.get_ai_report(sha)["model"] == "other-model"  # type: ignore[index]
        for bad in (2, -1):
            with pytest.raises(ApiError, match=r"^ai\.no_endpoint$"):
                api.ai_analyse(sha, preview["hash"], True, bad)
        assert len(other.posts) == 1
    finally:
        other.close()


def test_ignored_findings_are_not_sent(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    api.set_verdict(sha, FACT, "false_positive")
    ids = [f["id"] for f in json.loads(api.ai_preview(sha)["text"])["findings"]]
    assert FACT not in ids and ids
