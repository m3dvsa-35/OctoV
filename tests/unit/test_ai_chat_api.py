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
from tests.unit.test_relations_api import ENTRY, LEAF, MIDDLE, _chain

ANSWER = {
    "answer": "It starts a thread in another process.",
    "functions": [hex(MIDDLE), "0x999999"],
    "findings": ["rule:MADE-UP:0x0"],
    "iocs": [],
}


@pytest.fixture
def llm() -> Iterator[FakeLLM]:
    server = FakeLLM(json.dumps(ANSWER))
    yield server
    server.close()


def _api(tmp_path: Path, llm: FakeLLM | None) -> WorkbenchApi:
    config = Config()
    if llm is not None:
        config.ai.base_url = llm.base_url
        config.ai.model = "fake-model"
    return WorkbenchApi(
        config,
        settings_path=tmp_path / "ui.json",
        workspace_dir=tmp_path / "ws",
        cache_dir=tmp_path / "cache",
    )


def _open(api: WorkbenchApi, tmp_path: Path) -> str:
    sha = str(api.open_sample(str(_chain(tmp_path)))["sha256"])
    assert api._get(sha).pipeline.wait_slow(30)
    return sha


def _wait(api: WorkbenchApi, sha: str, timeout: float = 20) -> dict[str, Any]:
    end = time.monotonic() + timeout
    while True:
        job: dict[str, Any] = api.job_status(sha).get("ai_chat", {"state": "idle"})
        if job["state"] in ("done", "failed"):
            return job
        assert time.monotonic() < end, job
        time.sleep(0.02)


def _ask(api: WorkbenchApi, sha: str, question: str, focus: int | None = None) -> dict[str, Any]:
    preview = api.ai_chat_preview(sha, question, focus)
    api.ai_ask(sha, question, preview["hash"], focus)
    return _wait(api, sha)


def test_question_preview_is_what_gets_sent(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    preview = api.ai_chat_preview(sha, "  What does it do?  ")
    assert preview["chars"] == len(preview["text"]) and len(preview["hash"]) == 16
    assert preview["text"].startswith("EVIDENCE\n") and preview["text"].endswith("What does it do?")
    assert api.ai_preview(sha)["text"] in preview["text"]  # the same evidence as the report's
    assert preview["endpoints"] == [{"host": "127.0.0.1", "model": "fake-model", "local": True}]
    assert llm.requests == []
    assert _ask(api, sha, "What does it do?")["state"] == "done"
    (req,) = llm.posts
    assert req["body"]["messages"][1] == {"role": "user", "content": preview["text"]}
    assert "QUESTION" in req["body"]["messages"][0]["content"]


def test_nothing_sent_without_current_hash(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    seen = api.ai_chat_preview(sha, "Why?")["hash"]
    for call in (
        lambda: api.ai_ask(sha, "Why?", ""),
        lambda: api.ai_ask(sha, "Why not?", seen),  # another question than the one previewed
        lambda: api.ai_ask(sha, "Why?", seen, LEAF),  # another focus
    ):
        with pytest.raises(ApiError, match=r"^ai\.preview_changed$"):
            call()
    api.annotate(sha, "name", "start_thread", address=MIDDLE)  # the evidence changed
    with pytest.raises(ApiError, match=r"^ai\.preview_changed$"):
        api.ai_ask(sha, "Why?", seen)
    assert llm.requests == [] and "ai_chat" not in api.job_status(sha)
    assert api.get_ai_chat(sha) == {"turns": []}


def test_turn_is_stored_and_returned_with_valid_citations(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    assert _ask(api, sha, "What does it do?")["state"] == "done"
    (turn,) = api.get_ai_chat(sha)["turns"]
    assert turn["question"] == "What does it do?"
    assert turn["answer"] == "It starts a thread in another process."
    assert turn["functions"] == [MIDDLE] and turn["findings"] == [] and turn["dropped"] == 2
    assert turn["model"] == "fake-model" and turn["host"] == "127.0.0.1" and turn["created"] > 0
    # the conversation survives a restart of the app
    other = _api(tmp_path, llm)
    assert other.get_ai_chat(_open(other, tmp_path))["turns"] == [turn]


def test_history_goes_into_the_next_question(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    assert _ask(api, sha, "What does it do?")["state"] == "done"
    llm.reply = "Plain prose this time."
    preview = api.ai_chat_preview(sha, "And then?")
    assert "EARLIER QUESTIONS AND ANSWERS" in preview["text"]
    assert '"q": "What does it do?"' in preview["text"]
    assert '"a": "It starts a thread in another process."' in preview["text"]
    assert _ask(api, sha, "And then?")["state"] == "done"
    turns = api.get_ai_chat(sha)["turns"]
    assert [t["answer"] for t in turns][1] == "Plain prose this time." and turns[1][
        "functions"
    ] == []
    assert llm.posts[1]["body"]["messages"][1]["content"] == preview["text"]


def test_focus_function_outside_the_bundle(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    bundle_text = api.ai_preview(sha)["text"]
    assert hex(LEAF) not in [f["addr"] for f in json.loads(bundle_text)["functions"]]
    llm.reply = json.dumps({"answer": "It loads a constant.", "functions": [hex(LEAF)]})
    preview = api.ai_chat_preview(sha, "What is this function?", LEAF)
    assert "FUNCTION IN FOCUS" in preview["text"] and "0x1337" in preview["text"]
    assert _ask(api, sha, "What is this function?", LEAF)["state"] == "done"
    assert api.get_ai_chat(sha)["turns"][0]["functions"] == [LEAF]  # citable because it was sent
    inside = api.ai_chat_preview(sha, "And this one?", MIDDLE)["text"]
    assert "FUNCTION IN FOCUS" not in inside and f"function {MIDDLE:#x}" in inside
    with pytest.raises(ApiError, match=r"^ai\.bad_focus$"):
        api.ai_chat_preview(sha, "?", 0x1004)


@pytest.mark.parametrize("question", ["", "   ", "x" * 1001])
def test_bad_question(tmp_path: Path, llm: FakeLLM, question: str) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    with pytest.raises(ApiError, match=r"^ai\.bad_question$"):
        api.ai_chat_preview(sha, question)
    with pytest.raises(ApiError, match=r"^ai\.bad_question$"):
        api.ai_ask(sha, question, "0" * 16)
    assert llm.requests == []


def test_failure_is_failed_and_stores_nothing(tmp_path: Path, llm: FakeLLM) -> None:
    llm.mode = "429"
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    job = _ask(api, sha, "Why?")
    assert job["state"] == "failed" and job["error"] == "ai.rate_limit"
    assert api.get_ai_chat(sha) == {"turns": []}
    llm.mode = "ok"
    assert _ask(api, sha, "Why?")["state"] == "done" and len(api.get_ai_chat(sha)["turns"]) == 1


def test_one_request_at_a_time(tmp_path: Path, llm: FakeLLM) -> None:
    llm.mode, llm.delay = "slow", 1.0
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    first = api.ai_chat_preview(sha, "First?")
    api.ai_ask(sha, "First?", first["hash"])
    second = api.ai_chat_preview(sha, "Second?")
    with pytest.raises(ApiError, match=r"^ai\.busy$"):
        api.ai_ask(sha, "Second?", second["hash"])
    with pytest.raises(ApiError, match=r"^ai\.busy$"):
        api.ai_analyse(sha, api.ai_preview(sha)["hash"])  # the report request shares the slot
    assert _wait(api, sha)["state"] == "done"
    assert len(llm.posts) == 1 and len(api.get_ai_chat(sha)["turns"]) == 1


def test_closing_the_sample_stores_nothing(tmp_path: Path, llm: FakeLLM) -> None:
    llm.mode, llm.delay = "slow", 0.8
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    api.ai_ask(sha, "First?", api.ai_chat_preview(sha, "First?")["hash"])
    api.close_sample(sha)
    time.sleep(1.5)
    assert list((tmp_path / "cache").rglob("ai-chat*")) == []


def test_clear(tmp_path: Path, llm: FakeLLM) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    assert _ask(api, sha, "Why?")["state"] == "done"
    api.clear_ai_chat(sha)
    assert api.get_ai_chat(sha) == {"turns": []}
    assert "EARLIER QUESTIONS" not in api.ai_chat_preview(sha, "Again?")["text"]
    api.clear_ai_chat(sha)  # clearing nothing is fine


def test_conversation_is_capped(tmp_path: Path, llm: FakeLLM) -> None:
    from octov.core.ai.chat import MAX_TURNS

    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    for i in range(3):
        assert _ask(api, sha, f"Question {i}?")["state"] == "done"
    s = api._get(sha)
    turns = api.get_ai_chat(sha)["turns"]
    api._ai_chat_store(s, [dict(turns[0], question=f"old {i}") for i in range(MAX_TURNS + 5)])
    assert _ask(api, sha, "Newest?")["state"] == "done"
    kept = api.get_ai_chat(sha)["turns"]
    assert len(kept) == MAX_TURNS and kept[-1]["question"] == "Newest?"


def test_no_endpoint_and_not_ready(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    api = _api(tmp_path, None)  # remote default endpoint, no key
    sha = _open(api, tmp_path)
    preview = api.ai_chat_preview(sha, "Why?")
    assert preview["endpoints"] == []
    with pytest.raises(ApiError, match=r"^ai\.no_endpoint$"):
        api.ai_ask(sha, "Why?", preview["hash"])
    monkeypatch.setattr(Pipeline, "start_slow", lambda self, ctx, on_done=None: None)
    late = _api(tmp_path / "b", None)
    (tmp_path / "b").mkdir(exist_ok=True)
    sha2 = late.open_sample(str(_chain(tmp_path)))["sha256"]
    with pytest.raises(ApiError, match=r"^analysis\.not_ready$"):
        late.ai_chat_preview(sha2, "Why?")
    assert late.get_ai_chat(sha2) == {"turns": []}
    assert ENTRY == 0x1000


def test_clear_is_refused_while_a_question_is_running(tmp_path: Path, llm: FakeLLM) -> None:
    llm.mode, llm.delay = "slow", 0.8
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    api.ai_ask(sha, "First?", api.ai_chat_preview(sha, "First?")["hash"])
    with pytest.raises(ApiError, match=r"^ai\.busy$"):
        api.clear_ai_chat(sha)
    assert _wait(api, sha)["state"] == "done"
    api.clear_ai_chat(sha)
    assert api.get_ai_chat(sha) == {"turns": []}


@pytest.mark.parametrize("focus", ["abc", 4096.0, True, [4096]])
def test_focus_must_be_a_function_address(tmp_path: Path, llm: FakeLLM, focus: Any) -> None:
    api = _api(tmp_path, llm)
    sha = _open(api, tmp_path)
    with pytest.raises(ApiError, match=r"^ai\.bad_focus$"):
        api.ai_chat_preview(sha, "Why?", focus)
