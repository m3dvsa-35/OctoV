"""In-process stand-in for an OpenAI-compatible chat endpoint (tests never use the network)."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class FakeLLM:
    """Serves ``POST /v1/chat/completions`` on 127.0.0.1 and records every request.

    ``mode``: ``ok`` (answers ``reply``), ``401``, ``429``, ``500``, ``garbage`` (not JSON),
    ``empty`` (JSON without choices), ``slow`` (sleeps ``delay`` first), ``redirect`` (302 to
    ``redirect_to``).
    """

    def __init__(self, reply: str = "hello", mode: str = "ok") -> None:
        self.reply = reply
        self.mode = mode
        self.delay = 3.0
        self.redirect_to = "http://127.0.0.1:9/elsewhere"
        self.requests: list[dict[str, Any]] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # keep test output clean
                pass

            def _send(
                self, status: int, body: bytes, headers: dict[str, str] | None = None
            ) -> None:
                self.send_response(status)
                for key, value in (headers or {"Content-Type": "application/json"}).items():
                    self.send_header(key, value)
                try:
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass  # the client gave up (timeout tests)

            def do_GET(self) -> None:
                owner.requests.append({"method": "GET", "path": self.path})
                self._send(200, b"{}")

            def do_POST(self) -> None:
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
                owner.requests.append(
                    {
                        "method": "POST",
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                        "body": body,
                    }
                )
                mode = owner.mode
                if mode == "slow":
                    time.sleep(owner.delay)
                if mode in ("401", "429", "500"):
                    # echo the credential like some gateways do: the client must not repeat it
                    detail = f"bad key {self.headers.get('Authorization')}"
                    self._send(int(mode), json.dumps({"error": {"message": detail}}).encode())
                elif mode == "garbage":
                    self._send(200, b"<html>not json</html>")
                elif mode == "empty":
                    self._send(200, b'{"choices": []}')
                elif mode == "redirect":
                    self._send(302, b"", {"Location": owner.redirect_to})
                else:
                    reply = {
                        "choices": [{"message": {"role": "assistant", "content": owner.reply}}]
                    }
                    self._send(200, json.dumps(reply).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def posts(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["method"] == "POST"]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
