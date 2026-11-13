"""Minimal OpenAI-compatible chat client (standard library only).

Rules that keep evidence and the key safe: HTTPS to any host, plain HTTP only to this machine;
redirects are never followed; error texts never contain the key, the request or a response
body (a gateway may echo the credential back).
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

from octov.core.config import AIConfig

ErrorKind = Literal[
    "no_endpoint", "insecure_endpoint", "auth", "rate_limit", "timeout", "network", "bad_response"
]
MAX_REPLY_BYTES = 2 << 20


class AIError(Exception):
    def __init__(self, kind: ErrorKind, reason: str) -> None:
        super().__init__(reason)
        self.kind: ErrorKind = kind
        self.reason = reason


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class Endpoint:
    base_url: str
    model: str
    key: str | None = field(default=None, repr=False)

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def local(self) -> bool:
        """On this machine: nothing leaves it and no key is needed."""
        return _is_loopback(self.host)


def endpoints(cfg: AIConfig) -> list[Endpoint]:
    """The destinations the analyst can choose from: the main endpoint, then the fallback.

    A local endpoint needs no key and never gets one. The key goes to remote endpoints only,
    and to one host only: a remote fallback on another host than the main endpoint is left
    out, so one provider's key is never handed to another provider.
    """
    out: list[Endpoint] = []
    main = Endpoint(str(cfg.base_url or ""), str(cfg.model or ""), None)
    main_ok = bool(main.host and main.model and (main.local or cfg.api_key))
    if main_ok:
        out.append(Endpoint(main.base_url, main.model, None if main.local else cfg.api_key))
    if cfg.fallback_base_url and cfg.fallback_model:
        other = Endpoint(str(cfg.fallback_base_url), str(cfg.fallback_model), None)
        if other.host and other.local:
            out.append(other)
        elif (
            other.host and cfg.api_key and (main.local or not main.host or other.host == main.host)
        ):
            out.append(Endpoint(other.base_url, other.model, cfg.api_key))
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # the 3xx surfaces as an HTTPError: evidence and key go nowhere else


def _check(endpoint: Endpoint) -> None:
    parts = urlsplit(endpoint.base_url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and endpoint.local:
        return
    raise AIError("insecure_endpoint", "endpoint must be https:// (http:// only on this machine)")


def chat(endpoint: Endpoint, system: str, user: str, timeout_s: float) -> str:
    """One chat completion; the reply text. Raises :class:`AIError`."""
    _check(endpoint)
    body = json.dumps(
        {
            "model": endpoint.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
        }
    ).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if endpoint.key:
        headers["Authorization"] = f"Bearer {endpoint.key}"
    request = urllib.request.Request(
        endpoint.base_url.rstrip("/") + "/chat/completions",
        data=body,
        headers=headers,
        method="POST",
    )
    handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
    if endpoint.local:
        handlers.append(urllib.request.ProxyHandler({}))  # never route localhost through a proxy
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout_s) as response:
            raw = response.read(MAX_REPLY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code in (401, 403):
            raise AIError("auth", f"the endpoint rejected the key (HTTP {exc.code})") from None
        if exc.code == 429:
            raise AIError(
                "rate_limit", "the endpoint is rate-limiting requests (HTTP 429)"
            ) from None
        if 300 <= exc.code < 400:
            raise AIError("bad_response", f"the endpoint redirected (HTTP {exc.code})") from None
        raise AIError("network", f"the endpoint answered HTTP {exc.code}") from None
    except TimeoutError:
        raise AIError("timeout", f"no answer within {timeout_s:g} s") from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError | socket.timeout):
            raise AIError("timeout", f"no answer within {timeout_s:g} s") from None
        raise AIError("network", f"cannot reach {endpoint.host}") from None
    except OSError:
        raise AIError("network", f"cannot reach {endpoint.host}") from None
    except (http.client.HTTPException, ValueError):  # broken status line, bad URL in the config
        raise AIError("bad_response", "the endpoint did not speak HTTP properly") from None
    if len(raw) > MAX_REPLY_BYTES:
        raise AIError("bad_response", "the reply is too large")
    try:
        content = json.loads(raw.decode("utf-8"))["choices"][0]["message"]["content"]
    except (UnicodeDecodeError, ValueError, LookupError, TypeError):
        raise AIError("bad_response", "the endpoint did not return a chat completion") from None
    if not isinstance(content, str) or not content.strip():
        raise AIError("bad_response", "the model returned an empty answer")
    return content
