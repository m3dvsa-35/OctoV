from __future__ import annotations

from pathlib import Path

import pytest

from octov.core.config import DEFAULT_AI_MODEL, ConfigError, load_config


def test_defaults_without_file() -> None:
    cfg = load_config(None, env={})
    assert cfg.ai.model == DEFAULT_AI_MODEL == "nvidia/nemotron-3-ultra-550b-a55b:free"
    assert cfg.ai.base_url == "https://openrouter.ai/api/v1"
    assert cfg.ai.api_key is None
    assert cfg.ui.language == "en"
    assert cfg.ui.theme == "dark"


def test_yaml_overrides_defaults(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "ui:\n  language: az\n  theme: light\n"
        "ai:\n  fallback_base_url: http://localhost:11434/v1\n"
        "rules:\n  paths: [custom/rules.yaml]\n",
        encoding="utf-8",
    )
    cfg = load_config(path, env={})
    assert (cfg.ui.language, cfg.ui.theme) == ("az", "light")
    assert cfg.ai.fallback_base_url == "http://localhost:11434/v1"
    assert cfg.rules.paths == [tmp_path / "custom/rules.yaml"]


def test_api_key_only_comes_from_environment(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("ai:\n  api_key: sk-from-file\n", encoding="utf-8")
    assert load_config(path, env={}).ai.api_key is None
    assert load_config(path, env={"OCTOV_AI_KEY": "sk-env"}).ai.api_key == "sk-env"


def test_invalid_language_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("ui:\n  language: xx\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path, env={})


def test_missing_explicit_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yaml", env={})


def test_extension_defaults() -> None:
    cfg = load_config(None, env={})
    assert set(cfg.extensions) == {"capa", "floss"}
    capa = cfg.extensions["capa"]
    assert (capa.timeout_s, capa.max_size_mb, capa.max_memory_mb) == (600, 64, 4096)


def test_extension_overrides(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("extensions:\n  capa:\n    timeout_s: 30\n", encoding="utf-8")
    cfg = load_config(path, env={})
    assert cfg.extensions["capa"].timeout_s == 30
    assert cfg.extensions["floss"].timeout_s == 600


@pytest.mark.parametrize(
    "body",
    [
        "extensions:\n  capa:\n    colour: red\n",
        "extensions:\n  capa:\n    timeout_s: 0\n",
        "extensions:\n  ghidra:\n    timeout_s: 5\n",
    ],
)
def test_bad_extension_config_rejected(tmp_path: Path, body: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path, env={})
