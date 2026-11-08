from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import msgpack
import pytest

from octov.core.analysis.carve import Payload
from octov.core.session.session import APPLICATION_ID, SCHEMA_VERSION, Session, SessionError

SHA = "a" * 64
REPORT = {"path": "C:/x/a.exe", "size": 1, "hashes": {"sha256": SHA}}

V1_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE samples (sha256 TEXT PRIMARY KEY, path TEXT, size INTEGER, added_at REAL NOT NULL,
                      report BLOB NOT NULL);
CREATE TABLE artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256 TEXT NOT NULL REFERENCES
  samples(sha256) ON DELETE CASCADE, kind TEXT NOT NULL, created_at REAL NOT NULL, data BLOB NOT NULL);
CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL REFERENCES
  samples(sha256) ON DELETE CASCADE, offset INTEGER, text TEXT NOT NULL, created_at REAL NOT NULL);
"""


def _v1_file(path: Path) -> Path:
    con = sqlite3.connect(path)
    con.executescript(V1_SCHEMA)
    con.execute(f"PRAGMA application_id = {APPLICATION_ID}")
    con.execute("PRAGMA user_version = 1")
    con.execute(
        "INSERT INTO samples VALUES (?, ?, ?, ?, ?)",
        (SHA, "C:/x/a.exe", 1, time.time(), msgpack.packb(REPORT)),
    )
    con.execute(
        "INSERT INTO notes(sha256, offset, text, created_at) VALUES (?, ?, ?, ?)",
        (SHA, 0x1000, "entry", 1.0),
    )
    con.execute(
        "INSERT INTO notes(sha256, offset, text, created_at) VALUES (?, ?, ?, ?)",
        (SHA, None, "general", 2.0),
    )
    con.commit()
    con.close()
    return path


def _session(tmp_path: Path) -> Session:
    s = Session.create(tmp_path / "s.octov")
    s.add_sample(REPORT)
    return s


def test_schema_version_is_two() -> None:
    assert SCHEMA_VERSION == 2


def test_v1_file_is_migrated_and_notes_become_comments(tmp_path: Path) -> None:
    path = _v1_file(tmp_path / "old.octov")
    with Session.open(path) as s:
        comments = s.annotations(SHA, kind="comment")
        assert [(a.address, a.value) for a in comments] == [(0x1000, "entry"), (None, "general")]
        assert [(n.offset, n.text) for n in s.notes(SHA)] == [(0x1000, "entry"), (None, "general")]
    con = sqlite3.connect(path)
    assert con.execute("PRAGMA user_version").fetchone()[0] == 2
    con.close()


def test_name_annotation_replaces_previous_for_same_address(tmp_path: Path) -> None:
    with _session(tmp_path) as s:
        s.add_annotation(SHA, "name", "decrypt_config", address=0x1000)
        s.add_annotation(SHA, "name", "decrypt_cfg", address=0x1000)
        s.add_annotation(SHA, "name", "other", address=0x2000)
        names = {a.address: a.value for a in s.annotations(SHA, kind="name")}
        assert names == {0x1000: "decrypt_cfg", 0x2000: "other"}


def test_verdict_upserts_by_target(tmp_path: Path) -> None:
    with _session(tmp_path) as s:
        s.add_annotation(SHA, "verdict", "false_positive", target="rule:EVA-001:0x2000")
        s.add_annotation(SHA, "verdict", "confirmed", target="rule:EVA-001:0x2000")
        [v] = s.annotations(SHA, kind="verdict")
        assert (v.target, v.value) == ("rule:EVA-001:0x2000", "confirmed")


def test_comments_and_bookmarks_append_and_delete(tmp_path: Path) -> None:
    with _session(tmp_path) as s:
        a = s.add_annotation(SHA, "comment", "one", address=0x10)
        s.add_annotation(SHA, "comment", "two", address=0x10)
        s.add_annotation(SHA, "bookmark", "look here", address=0x20)
        assert len(s.annotations(SHA, kind="comment")) == 2
        s.delete_annotation(a)
        assert [x.value for x in s.annotations(SHA)] == ["two", "look here"]


def test_invalid_annotation_kind_rejected(tmp_path: Path) -> None:
    with _session(tmp_path) as s, pytest.raises(SessionError):
        s.add_annotation(SHA, "tag", "x")


def test_payload_roundtrip(tmp_path: Path) -> None:
    payload = Payload(0x400, 3, "pe", "overlay", "b" * 64)
    with _session(tmp_path) as s:
        s.add_payload(SHA, payload, b"MZ\x00")
        assert s.payload_bytes("b" * 64) == b"MZ\x00"
        assert s.payload_bytes("c" * 64) is None
        [row] = s.payloads(SHA)
        assert row["sha256"] == "b" * 64 and row["where"] == "overlay" and row["offset"] == 0x400


def test_newer_schema_still_rejected(tmp_path: Path) -> None:
    path = tmp_path / "s.octov"
    Session.create(path).close()
    con = sqlite3.connect(path)
    con.execute("PRAGMA user_version = 3")
    con.commit()
    con.close()
    with pytest.raises(SessionError):
        Session.open(path)
