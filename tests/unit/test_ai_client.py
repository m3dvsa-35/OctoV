from __future__ import annotations

import time
from collections.abc import Iterator

import pytest

from octov.core.ai import client as client_mod
from octov.core.ai.client import AIError, Endpoint, chat, endpoints
from octov.core.config import AIConfig
from tests.fixtures.fake_llm import FakeLLM

KEY = "sk-test-not-a-real-key-0123456789"


@pytest.fixture
def llm() -> Iterator[FakeLLM]:
    server = FakeLLM()
    yield server
    server.close()


def test_chat_returns_the_message_content(llm: FakeLLM) -> None:
    llm.reply = "the answer"
    out = chat(Endpoint(llm.base_url, "m1", KEY), "you are a test", "evidence here", 10)
    assert out == "the answer"
    (req,) = llm.posts
    assert req["path"] == "/v1/chat/completions"
    assert req["authorization"] == f"Bearer {KEY}"
    assert req["body"]["model"] == "m1"
    assert req["body"]["messages"] == [
        {"role": "system", "content": "you are a test"},
        {"role": "user", "content": "evidence here"},
    ]


def test_local_endpoint_sends_no_authorization_without_a_key(llm: FakeLLM) -> None:
    chat(Endpoint(llm.base_url, "m1", None), "s", "u", 10)
    assert llm.posts[0]["authorization"] is None


@pytest.mark.parametrize(
    ("mode", "kind"), [("401", "auth"), ("429", "rate_limit"), ("500", "network")]
)
def test_http_errors_have_a_kind_and_hide_the_key(llm: FakeLLM, mode: str, kind: str) -> None:
    llm.mode = mode
    with pytest.raises(AIError) as err:
        chat(Endpoint(llm.base_url, "m1", KEY), "s", "the evidence text", 10)
    assert err.value.kind == kind
    for text in (err.value.reason, str(err.value), repr(err.value)):
        assert KEY not in text and "Bearer" not in text and "the evidence text" not in text


def test_timeout(llm: FakeLLM) -> None:
    llm.mode = "slow"
    start = time.monotonic()
    with pytest.raises(AIError) as err:
        chat(Endpoint(llm.base_url, "m1", None), "s", "u", 0.5)
    assert err.value.kind == "timeout" and time.monotonic() - start < 2.5


@pytest.mark.parametrize("mode", ["garbage", "empty"])
def test_garbage_and_missing_fields_are_bad_response(llm: FakeLLM, mode: str) -> None:
    llm.mode = mode
    with pytest.raises(AIError) as err:
        chat(Endpoint(llm.base_url, "m1", None), "s", "u", 10)
    assert err.value.kind == "bad_response"


def test_connection_refused_is_network() -> None:
    import socket

    with socket.socket() as probe:  # a port nobody listens on
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(AIError) as err:
        chat(Endpoint(f"http://127.0.0.1:{port}/v1", "m1", None), "s", "u", 15)
    assert err.value.kind == "network" and str(port) not in err.value.reason


@pytest.mark.parametrize(
    "url", ["http://example.com/v1", "ftp://127.0.0.1/v1", "file:///c:/x", "example.com/v1", ""]
)
def test_plain_http_to_a_remote_host_is_refused_without_connecting(url: str) -> None:
    start = time.monotonic()
    with pytest.raises(AIError) as err:
        chat(Endpoint(url, "m1", KEY), "s", "u", 10)
    assert err.value.kind == "insecure_endpoint" and time.monotonic() - start < 0.5


def test_redirect_is_not_followed(llm: FakeLLM) -> None:
    other = FakeLLM("from the other host")
    try:
        llm.mode = "redirect"
        llm.redirect_to = f"{other.base_url}/chat/completions"
        with pytest.raises(AIError) as err:
            chat(Endpoint(llm.base_url, "m1", KEY), "s", "u", 10)
        assert err.value.kind == "bad_response"
        assert other.requests == []  # neither the evidence nor the key went anywhere else
    finally:
        other.close()


def test_endpoints_order_and_key_rules() -> None:
    remote = "https://openrouter.ai/api/v1"
    cfg = AIConfig(base_url=remote, model="m", api_key=None)
    assert endpoints(cfg) == []  # a remote endpoint without a key cannot be used
    cfg = AIConfig(base_url=remote, model="m", api_key=KEY)
    (only,) = endpoints(cfg)
    assert only.host == "openrouter.ai" and not only.local and only.key == KEY
    cfg = AIConfig(
        base_url=remote,
        model="m",
        api_key=KEY,
        fallback_base_url="http://localhost:11434/v1",
        fallback_model="qwen",
    )
    first, second = endpoints(cfg)
    assert (first.host, second.host) == ("openrouter.ai", "localhost")
    assert second.local and second.key is None and second.model == "qwen"  # the key stays home
    cfg = AIConfig(base_url="http://127.0.0.1:1234/v1", model="local", api_key=None)
    assert [e.local for e in endpoints(cfg)] == [True]
    assert KEY not in repr(first)


def test_the_key_is_never_offered_to_another_remote_host() -> None:
    cfg = AIConfig(
        base_url="https://openrouter.ai/api/v1",
        model="m",
        api_key=KEY,
        fallback_base_url="https://other-provider.example/v1",
        fallback_model="x",
    )
    assert [e.host for e in endpoints(cfg)] == ["openrouter.ai"]  # one provider's key, one provider
    cfg.fallback_base_url = "https://openrouter.ai/api/v1"  # the same host, another model: fine
    assert [(e.host, e.model, e.key) for e in endpoints(cfg)] == [
        ("openrouter.ai", "m", KEY),
        ("openrouter.ai", "x", KEY),
    ]
    local_first = AIConfig(
        base_url="http://localhost:11434/v1",
        model="qwen",
        api_key=KEY,
        fallback_base_url="https://openrouter.ai/api/v1",
        fallback_model="m",
    )
    first, second = endpoints(local_first)
    assert first.local and first.key is None and second.key == KEY  # the key's own host only


def test_there_is_no_automatic_fallback_helper() -> None:
    # sending to an endpoint the analyst did not confirm must not be one call away
    assert not hasattr(client_mod, "ask")


def test_error_text_never_contains_key_or_body() -> None:
    err = AIError("auth", "rejected")
    assert str(err) == "rejected" and err.kind == "auth"
