"""Configuration loading (``config.yaml``) with safe defaults.

Secrets are never read from the YAML file: the AI API key comes only from the
``OCTOV_AI_KEY`` environment variable.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from octov.core.i18n import LANGUAGES

DEFAULT_AI_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
DEFAULT_AI_BASE_URL = "https://openrouter.ai/api/v1"
API_KEY_ENV = "OCTOV_AI_KEY"
THEMES = ("dark", "light")
_REPO_ROOT = Path(__file__).resolve().parents[3]


class ConfigError(Exception):
    """Raised for unreadable or invalid configuration."""


@dataclass
class AIConfig:
    base_url: str = DEFAULT_AI_BASE_URL
    model: str = DEFAULT_AI_MODEL
    api_key: str | None = None
    fallback_base_url: str | None = None
    fallback_model: str | None = None
    timeout_s: float = 60.0


@dataclass
class UIConfig:
    language: str = "en"
    theme: str = "dark"


@dataclass
class StaticConfig:
    max_file_size_mb: int = 256


@dataclass
class DynamicConfig:
    enabled: bool = False
    symbol_cache: Path = Path("~/.octov/symbols")
    symbol_server: str = "https://msdl.microsoft.com/download/symbols"


def _default_rule_paths() -> list[Path]:
    return [
        _REPO_ROOT / "rules" / "evasion_patterns.yaml",
        _REPO_ROOT / "rules" / "pic_patterns.yaml",
    ]


@dataclass
class RulesConfig:
    paths: list[Path] = field(default_factory=_default_rule_paths)


@dataclass
class ExtensionConfig:
    timeout_s: int = 600
    max_size_mb: int = 64
    max_memory_mb: int = 4096


EXTENSION_IDS = ("capa", "floss")


@dataclass
class Config:
    ai: AIConfig = field(default_factory=AIConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    static: StaticConfig = field(default_factory=StaticConfig)
    dynamic: DynamicConfig = field(default_factory=DynamicConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    extensions: dict[str, ExtensionConfig] = field(
        default_factory=lambda: {e: ExtensionConfig() for e in EXTENSION_IDS}
    )


def _section(raw: Mapping[str, Any], name: str) -> dict[str, Any]:
    value = raw.get(name) or {}
    if not isinstance(value, dict):
        raise ConfigError(f"'{name}' must be a mapping")
    return value


def load_config(path: str | Path | None, env: Mapping[str, str] | None = None) -> Config:
    """Load configuration from ``path`` (``None`` = defaults only)."""
    env = os.environ if env is None else env
    raw: dict[str, Any] = {}
    base_dir = Path.cwd()
    if path is not None:
        path = Path(path)
        base_dir = path.parent
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except OSError as exc:
            raise ConfigError(f"cannot read config {path}: {exc}") from exc
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError("config root must be a mapping")
        raw = loaded

    cfg = Config()
    ai = _section(raw, "ai")
    for key, value in ai.items():
        if key != "api_key" and hasattr(cfg.ai, key):  # secrets only via environment
            setattr(cfg.ai, key, value)
    cfg.ai.api_key = env.get(API_KEY_ENV) or None

    ui = _section(raw, "ui")
    cfg.ui.language = str(ui.get("language", cfg.ui.language))
    cfg.ui.theme = str(ui.get("theme", cfg.ui.theme))
    if cfg.ui.language not in LANGUAGES:
        raise ConfigError(
            f"unsupported language {cfg.ui.language!r}; use one of {sorted(LANGUAGES)}"
        )
    if cfg.ui.theme not in THEMES:
        raise ConfigError(f"unsupported theme {cfg.ui.theme!r}; use one of {THEMES}")

    static = _section(raw, "static")
    cfg.static.max_file_size_mb = int(static.get("max_file_size_mb", cfg.static.max_file_size_mb))

    dyn = _section(raw, "dynamic")
    cfg.dynamic.enabled = bool(dyn.get("enabled", cfg.dynamic.enabled))
    if "symbol_cache" in dyn:
        cfg.dynamic.symbol_cache = Path(dyn["symbol_cache"])
    cfg.dynamic.symbol_server = str(dyn.get("symbol_server", cfg.dynamic.symbol_server))

    rules = _section(raw, "rules")
    if "paths" in rules:
        cfg.rules.paths = [base_dir / p for p in rules["paths"]]

    for ext_id, values in _section(raw, "extensions").items():
        if ext_id not in cfg.extensions:
            raise ConfigError(f"unknown extension {ext_id!r}; use one of {EXTENSION_IDS}")
        if not isinstance(values, dict):
            raise ConfigError(f"'extensions.{ext_id}' must be a mapping")
        target = cfg.extensions[ext_id]
        for key, value in values.items():
            if not hasattr(target, key):
                raise ConfigError(f"unknown setting extensions.{ext_id}.{key}")
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ConfigError(f"extensions.{ext_id}.{key} must be a positive integer")
            setattr(target, key, value)
    return cfg
