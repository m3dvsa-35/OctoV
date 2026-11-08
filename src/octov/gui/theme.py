"""Qt stylesheets for the OctoV workbench (dark / light)."""

from __future__ import annotations

_TEMPLATE = """
QWidget {{ background: {bg}; color: {fg}; font-family: "Segoe UI", sans-serif; font-size: 10pt; }}
QMainWindow::separator {{ background: {border}; width: 3px; height: 3px; }}
QDockWidget::title {{ background: {panel}; padding: 4px 8px; border-bottom: 1px solid {border}; }}
QMenuBar, QMenu {{ background: {panel}; }}
QMenu::item:selected, QMenuBar::item:selected {{ background: {accent}; color: {accent_fg}; }}
QPlainTextEdit, QTextEdit, QListWidget, QTableWidget {{
    background: {base}; border: 1px solid {border}; selection-background-color: {accent};
    selection-color: {accent_fg};
}}
QPlainTextEdit, QTextEdit {{ font-family: "Cascadia Mono", Consolas, monospace; }}
QHeaderView::section {{ background: {panel}; color: {fg}; border: 0; padding: 4px; }}
QTabBar::tab {{ background: {panel}; padding: 4px 10px; border: 1px solid {border}; }}
QTabBar::tab:selected {{ background: {base}; border-bottom: 2px solid {accent}; }}
QStatusBar {{ background: {panel}; border-top: 1px solid {border}; }}
QLabel#placeholder {{ color: {muted}; }}
"""

PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "bg": "#1b1e23",
        "panel": "#23272e",
        "base": "#15171b",
        "fg": "#d7dae0",
        "muted": "#7f8794",
        "border": "#343a44",
        "accent": "#2f81f7",
        "accent_fg": "#ffffff",
    },
    "light": {
        "bg": "#f5f6f8",
        "panel": "#e8ebef",
        "base": "#ffffff",
        "fg": "#1f2328",
        "muted": "#6e7781",
        "border": "#c9ced6",
        "accent": "#0969da",
        "accent_fg": "#ffffff",
    },
}

SEVERITY_COLORS: dict[str, str] = {
    "high": "#e5534b",
    "medium": "#d29922",
    "low": "#539bf5",
    "info": "#7f8794",
}


def stylesheet(theme: str) -> str:
    return _TEMPLATE.format(**PALETTES[theme])
