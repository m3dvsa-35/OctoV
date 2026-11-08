"""Loopback development server: serves the built UI and a token-protected JSON-RPC endpoint.

Used to run the UI in a normal browser while developing (the desktop app talks
to the API through pywebview's in-process bridge instead and opens no port).

Security model: binds to 127.0.0.1 only, every RPC call must carry the random
per-run token in ``X-OctoV-Token``, only public :class:`WorkbenchApi` methods are
callable, no CORS headers are sent, and static paths cannot escape ``static_dir``.
"""

from __future__ import annotations

import hmac
import inspect
import json
import mimetypes
import secrets
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from octov.app.api import ApiError, WorkbenchApi

MAX_BODY = 1 << 20


def api_methods(api: WorkbenchApi) -> dict[str, Any]:
    return {
        name: getattr(api, name)
        for name, member in inspect.getmembers(type(api), inspect.isfunction)
        if not name.startswith("_")
    }


def make_server(
    api: WorkbenchApi, static_dir: Path, port: int = 0, host: str = "127.0.0.1"
) -> tuple[ThreadingHTTPServer, str]:
    token = secrets.token_urlsafe(24)
    methods = api_methods(api)
    root = static_dir.resolve()

    class Handler(BaseHTTPRequestHandler):
        server_version = "OctoV"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: object) -> None:
            self._send(status, json.dumps(payload).encode(), "application/json")

        def do_GET(self) -> None:
            rel = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path).lstrip("/")
            target = (root / (rel or "index.html")).resolve()
            if not target.is_relative_to(root) or not target.is_file():
                self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
                return
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            self._send(HTTPStatus.OK, target.read_bytes(), ctype)

        def do_POST(self) -> None:
            if urllib.parse.urlsplit(self.path).path != "/rpc":
                self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
                return
            supplied = self.headers.get("X-OctoV-Token", "")
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid token"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request too large"})
                return
            try:
                request = json.loads(self.rfile.read(length))
                method = methods.get(str(request.get("method")))
                params = request.get("params") or {}
                if not isinstance(params, dict):
                    raise ValueError("params must be an object")
            except (ValueError, AttributeError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "malformed request"})
                return
            if method is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "unknown method"})
                return
            try:
                self._json(HTTPStatus.OK, {"result": method(**params)})
            except ApiError as exc:
                self._json(HTTPStatus.OK, {"error": str(exc)})
            except TypeError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": f"bad parameters: {exc}"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server, token
