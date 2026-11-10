"""Desktop shell: a native window (Edge WebView2 via pywebview) hosting the web UI.

The UI talks to :class:`DesktopApi` through pywebview's in-process JS bridge, so
API calls never touch the network. pywebview's built-in static server (loopback
only) is used just to serve the bundled HTML/JS, because Chromium refuses to
load ES modules from ``file://``.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from octov.app.api import WorkbenchApi
from octov.core.config import ConfigError, load_config

DIST = Path(__file__).resolve().parents[1] / "webui" / "dist"
BUILD_HINT = (
    "The web UI is not built yet. Run:  "
    "python scripts/npm.py install && python scripts/npm.py run build"
)


class DesktopApi(WorkbenchApi):
    """Adds native file dialogs. Private attributes are not exposed to JavaScript."""

    _window: object | None = None

    def capabilities(self) -> dict[str, bool]:
        return {"native_dialogs": True}

    def choose_file(self) -> str | None:
        import webview

        if self._window is None:
            return None
        result = self._window.create_file_dialog(webview.FileDialog.OPEN)  # type: ignore[attr-defined]
        return str(result[0]) if result else None

    def choose_save_path(self, suggested: str) -> str | None:
        import webview

        if self._window is None:
            return None
        result = self._window.create_file_dialog(  # type: ignore[attr-defined]
            webview.FileDialog.SAVE, save_filename=suggested
        )
        if not result:
            return None
        return str(result if isinstance(result, str) else result[0])


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="octov-gui", description="OctoV desktop workbench")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--debug", action="store_true", help="enable WebView2 developer tools")
    parser.add_argument("samples", nargs="*", type=Path)
    args = parser.parse_args(argv)

    index = DIST / "index.html"
    if not index.is_file():
        print(BUILD_HINT, file=sys.stderr)
        return 2
    config_path = args.config
    if config_path is None and Path("config.yaml").is_file():
        config_path = Path("config.yaml")
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    import webview

    api = DesktopApi(config)
    for sample in args.samples:
        api.open_sample(str(sample))
    window = webview.create_window(
        "OctoV",
        url=str(index),
        js_api=api,
        width=1480,
        height=920,
        min_size=(1100, 680),
        background_color="#121212",
        text_select=True,
    )
    api._window = window
    try:
        webview.start(gui="edgechromium", http_server=True, debug=args.debug, private_mode=True)
    finally:
        api.shutdown()  # stop Ghidra workers
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
