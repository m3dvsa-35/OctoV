"""Guard: API keys must live only in the environment (OCTOV_AI_KEY), never in the repo."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache", "site"}
KEY_PATTERNS = [
    re.compile(r"sk-or-v1-[0-9a-f]{32,}"),  # OpenRouter
    re.compile(r"sk-[A-Za-z0-9]{40,}"),  # generic OpenAI-style
]


def _files() -> list[Path]:
    return [
        p
        for p in ROOT.rglob("*")
        if p.is_file() and not SKIP_DIRS.intersection(p.relative_to(ROOT).parts)
    ]


def test_repository_contains_no_api_keys() -> None:
    leaks = []
    for path in _files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(p.search(text) for p in KEY_PATTERNS):
            leaks.append(str(path.relative_to(ROOT)))
    assert leaks == [], f"possible API key committed in: {leaks}"
