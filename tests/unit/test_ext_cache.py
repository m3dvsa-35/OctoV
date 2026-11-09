from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from octov.ext.cache import cache_file, load, store

SHA = "ab" * 32


def test_round_trip(tmp_path: Path) -> None:
    path = cache_file(tmp_path, SHA, "capa", "10.0.0", "v10.0.0")
    assert path == tmp_path / SHA / "capa-10.0.0-v10.0.0.json.gz"
    store(path, {"rules": {"x": 1}})
    assert load(path) == {"rules": {"x": 1}}
    assert gzip.decompress(path.read_bytes()).startswith(b"{")


def test_no_rules_version_and_sanitised_names(tmp_path: Path) -> None:
    path = cache_file(tmp_path, SHA, "floss", "3.2.0+local/x", None)
    assert path.name == "floss-3.2.0_local_x-none.json.gz"
    assert path.parent == tmp_path / SHA


def test_version_mismatch_is_miss(tmp_path: Path) -> None:
    store(cache_file(tmp_path, SHA, "capa", "10.0.0", "v10.0.0"), {"a": 1})
    assert load(cache_file(tmp_path, SHA, "capa", "10.0.1", "v10.0.0")) is None


def test_corrupt_cache_is_miss(tmp_path: Path) -> None:
    path = cache_file(tmp_path, SHA, "capa", "10.0.0", "v10.0.0")
    store(path, {"a": list(range(1000))})
    path.write_bytes(path.read_bytes()[:20])
    assert load(path) is None
    path.write_bytes(gzip.compress(b"[1, 2]"))
    assert load(path) is None


def test_store_is_atomic(tmp_path: Path) -> None:
    path = cache_file(tmp_path, SHA, "capa", "10.0.0", "v10.0.0")
    with pytest.raises(TypeError):
        store(path, {"bad": object()})
    assert not path.exists()
    assert not path.parent.exists() or not any(path.parent.iterdir())
