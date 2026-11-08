"""`.octov` investigation sessions: a single SQLite file with msgpack-encoded payloads.

A session stores analysed samples (full static/dynamic reports), derived
artifacts (IOCs, YARA/Sigma rules, AI findings, ...), analyst notes and
arbitrary metadata such as GUI layout. Everything stays local.

Usage::

    with Session.create("case.octov", name="IR-2026-001") as s:
        sha = s.add_sample(parse_pe("sample.exe"))
        s.add_artifact(sha, "ioc", {"type": "domain", "value": "bad.example"})

Changes are committed when the ``with`` block exits cleanly and rolled back if
it raises.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, Self

import msgpack

APPLICATION_ID = 0x4F435456  # "OCTV"
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE samples (
    sha256   TEXT PRIMARY KEY,
    path     TEXT,
    size     INTEGER,
    added_at REAL NOT NULL,
    report   BLOB NOT NULL
);
CREATE TABLE artifacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256     TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    created_at REAL NOT NULL,
    data       BLOB NOT NULL
);
CREATE INDEX idx_artifacts_sample_kind ON artifacts(sha256, kind);
CREATE TABLE notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256     TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
    offset     INTEGER,
    text       TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


class SessionError(Exception):
    """Raised for invalid session files or misuse of a session."""


class _HasToDict(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class SampleRow:
    sha256: str
    path: str | None
    size: int | None
    added_at: float


@dataclass(frozen=True)
class Artifact:
    id: int
    sha256: str
    kind: str
    created_at: float
    data: Any


@dataclass(frozen=True)
class Note:
    id: int
    sha256: str
    offset: int | None
    text: str
    created_at: float


def _pack(value: Any) -> bytes:
    packed: bytes = msgpack.packb(value, use_bin_type=True)
    return packed


def _unpack(blob: bytes) -> Any:
    return msgpack.unpackb(blob, raw=False, strict_map_key=False)


class Session:
    """An open `.octov` session. Construct with :meth:`create` or :meth:`open`."""

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._con: sqlite3.Connection | None = connection

    # -- lifecycle -------------------------------------------------------

    @classmethod
    def create(cls, path: str | Path, *, name: str | None = None) -> Session:
        path = Path(path)
        if path.exists():
            raise SessionError(f"session already exists: {path}")
        con = sqlite3.connect(path)
        try:
            con.executescript(_SCHEMA)
            con.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            con.execute("PRAGMA foreign_keys = ON")
            session = cls(path, con)
            session.set_meta("created_at", time.time())
            session.set_meta("name", name or path.stem)
            con.commit()
        except Exception:
            con.close()
            path.unlink(missing_ok=True)
            raise
        return session

    @classmethod
    def open(cls, path: str | Path) -> Session:
        path = Path(path)
        if not path.is_file():
            raise SessionError(f"session not found: {path}")
        con = sqlite3.connect(path)
        try:
            app_id = con.execute("PRAGMA application_id").fetchone()[0]
            version = con.execute("PRAGMA user_version").fetchone()[0]
        except sqlite3.DatabaseError as exc:
            con.close()
            raise SessionError(f"not an OctoV session: {path}") from exc
        if app_id != APPLICATION_ID:
            con.close()
            raise SessionError(f"not an OctoV session: {path}")
        if version > SCHEMA_VERSION:
            con.close()
            raise SessionError(
                f"session schema v{version} is newer than supported v{SCHEMA_VERSION}"
            )
        con.execute("PRAGMA foreign_keys = ON")
        return cls(path, con)

    def commit(self) -> None:
        self._db.commit()

    def close(self) -> None:
        if self._con is not None:
            self._con.close()
            self._con = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._con is not None:
            if exc_type is None:
                self._con.commit()
            else:
                self._con.rollback()
        self.close()

    @property
    def _db(self) -> sqlite3.Connection:
        if self._con is None:
            raise SessionError("session is closed")
        return self._con

    # -- metadata --------------------------------------------------------

    def set_meta(self, key: str, value: Any) -> None:
        self._db.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, _pack(value)),
        )

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return _unpack(row[0]) if row else default

    # -- samples ---------------------------------------------------------

    def add_sample(self, report: Mapping[str, Any] | _HasToDict) -> str:
        """Store (or replace) a sample report. Returns its SHA-256."""
        data: Mapping[str, Any] = report.to_dict() if hasattr(report, "to_dict") else report
        sha = (data.get("hashes") or {}).get("sha256")
        if not isinstance(sha, str) or len(sha) != 64:
            raise SessionError("report must contain hashes.sha256")
        self._db.execute(
            "INSERT INTO samples(sha256, path, size, added_at, report) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(sha256) DO UPDATE SET path = excluded.path, size = excluded.size, "
            "report = excluded.report",
            (sha, data.get("path"), data.get("size"), time.time(), _pack(dict(data))),
        )
        return sha

    def get_sample(self, sha256: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT report FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
        return _unpack(row[0]) if row else None

    def list_samples(self) -> list[SampleRow]:
        rows = self._db.execute(
            "SELECT sha256, path, size, added_at FROM samples ORDER BY added_at, sha256"
        ).fetchall()
        return [SampleRow(*r) for r in rows]

    # -- artifacts & notes ----------------------------------------------

    def add_artifact(self, sha256: str, kind: str, data: Any) -> int:
        try:
            cur = self._db.execute(
                "INSERT INTO artifacts(sha256, kind, created_at, data) VALUES (?, ?, ?, ?)",
                (sha256, kind, time.time(), _pack(data)),
            )
        except sqlite3.IntegrityError as exc:
            raise SessionError(f"unknown sample {sha256}") from exc
        return int(cur.lastrowid or 0)

    def artifacts(self, sha256: str, kind: str | None = None) -> list[Artifact]:
        query = "SELECT id, sha256, kind, created_at, data FROM artifacts WHERE sha256 = ?"
        params: tuple[str, ...] = (sha256,)
        if kind is not None:
            query += " AND kind = ?"
            params += (kind,)
        rows = self._db.execute(query + " ORDER BY id", params).fetchall()
        return [Artifact(i, s, k, c, _unpack(d)) for i, s, k, c, d in rows]

    def add_note(self, sha256: str, text: str, offset: int | None = None) -> int:
        try:
            cur = self._db.execute(
                "INSERT INTO notes(sha256, offset, text, created_at) VALUES (?, ?, ?, ?)",
                (sha256, offset, text, time.time()),
            )
        except sqlite3.IntegrityError as exc:
            raise SessionError(f"unknown sample {sha256}") from exc
        return int(cur.lastrowid or 0)

    def notes(self, sha256: str) -> list[Note]:
        rows = self._db.execute(
            "SELECT id, sha256, offset, text, created_at FROM notes WHERE sha256 = ? ORDER BY id",
            (sha256,),
        ).fetchall()
        return [Note(*r) for r in rows]
