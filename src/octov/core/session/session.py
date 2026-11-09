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

import functools
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Concatenate, ParamSpec, Protocol, Self, TypeVar

import msgpack

from octov.core.analysis.carve import Payload

APPLICATION_ID = 0x4F435456  # "OCTV"
SCHEMA_VERSION = 2
ANNOTATION_KINDS = ("name", "comment", "bookmark", "verdict")

_SCHEMA = (
    """
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
"""
    + """
-- v2 tables (also created by the v1 -> v2 migration)
"""
)
_V2_TABLES = """
CREATE TABLE annotations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256     TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('name', 'comment', 'bookmark', 'verdict')),
    address    INTEGER,
    target     TEXT,
    value      TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX idx_annotations_sample ON annotations(sha256, kind);
CREATE TABLE payloads (
    sha256        TEXT PRIMARY KEY,
    parent_sha256 TEXT NOT NULL REFERENCES samples(sha256) ON DELETE CASCADE,
    offset        INTEGER NOT NULL,
    size          INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    location      TEXT NOT NULL,
    data          BLOB NOT NULL
);
"""
_MIGRATE_V1 = (
    _V2_TABLES
    + """
INSERT INTO annotations(sha256, kind, address, target, value, created_at)
    SELECT sha256, 'comment', offset, NULL, text, created_at FROM notes ORDER BY id;
DROP TABLE notes;
"""
)


P = ParamSpec("P")
R = TypeVar("R")


def _serialized(fn: Callable[Concatenate[Session, P], R]) -> Callable[Concatenate[Session, P], R]:
    @functools.wraps(fn)
    def wrapper(session: Session, /, *args: P.args, **kwargs: P.kwargs) -> R:
        with session._lock:
            return fn(session, *args, **kwargs)

    return wrapper


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
class Annotation:
    id: int
    sha256: str
    kind: str
    address: int | None
    target: str | None
    value: str
    created_at: float


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
        # One connection is shared by the UI/dev-server threads: one call at a time.
        self._lock = threading.RLock()

    # -- lifecycle -------------------------------------------------------

    @classmethod
    def create(cls, path: str | Path, *, name: str | None = None) -> Session:
        path = Path(path)
        if path.exists():
            raise SessionError(f"session already exists: {path}")
        con = sqlite3.connect(path, check_same_thread=False)  # threadsafety 3: serialized
        try:
            con.executescript(_SCHEMA + _V2_TABLES)
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
        con = sqlite3.connect(path, check_same_thread=False)  # threadsafety 3: serialized
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
        if version < SCHEMA_VERSION:
            try:
                con.executescript(
                    "BEGIN;" + _MIGRATE_V1 + f"PRAGMA user_version = {SCHEMA_VERSION};COMMIT;"
                )
            except sqlite3.DatabaseError as exc:
                con.rollback()
                con.close()
                raise SessionError(f"cannot migrate session {path}: {exc}") from exc
        con.execute("PRAGMA foreign_keys = ON")
        return cls(path, con)

    @_serialized
    def commit(self) -> None:
        self._db.commit()

    @_serialized
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

    @_serialized
    def set_meta(self, key: str, value: Any) -> None:
        self._db.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, _pack(value)),
        )

    @_serialized
    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return _unpack(row[0]) if row else default

    # -- samples ---------------------------------------------------------

    @_serialized
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

    @_serialized
    def get_sample(self, sha256: str) -> dict[str, Any] | None:
        row = self._db.execute("SELECT report FROM samples WHERE sha256 = ?", (sha256,)).fetchone()
        return _unpack(row[0]) if row else None

    @_serialized
    def list_samples(self) -> list[SampleRow]:
        rows = self._db.execute(
            "SELECT sha256, path, size, added_at FROM samples ORDER BY added_at, sha256"
        ).fetchall()
        return [SampleRow(*r) for r in rows]

    # -- artifacts & notes ----------------------------------------------

    @_serialized
    def add_artifact(self, sha256: str, kind: str, data: Any) -> int:
        try:
            cur = self._db.execute(
                "INSERT INTO artifacts(sha256, kind, created_at, data) VALUES (?, ?, ?, ?)",
                (sha256, kind, time.time(), _pack(data)),
            )
        except sqlite3.IntegrityError as exc:
            raise SessionError(f"unknown sample {sha256}") from exc
        return int(cur.lastrowid or 0)

    @_serialized
    def artifacts(self, sha256: str, kind: str | None = None) -> list[Artifact]:
        query = "SELECT id, sha256, kind, created_at, data FROM artifacts WHERE sha256 = ?"
        params: tuple[str, ...] = (sha256,)
        if kind is not None:
            query += " AND kind = ?"
            params += (kind,)
        rows = self._db.execute(query + " ORDER BY id", params).fetchall()
        return [Artifact(i, s, k, c, _unpack(d)) for i, s, k, c, d in rows]

    # -- annotations (analyst corrections) ----------------------------------------

    @_serialized
    def add_annotation(
        self,
        sha256: str,
        kind: str,
        value: str,
        address: int | None = None,
        target: str | None = None,
    ) -> int:
        """Names replace per address and verdicts per target; comments/bookmarks append."""
        if kind not in ANNOTATION_KINDS:
            raise SessionError(f"invalid annotation kind {kind!r}")
        if kind == "name":
            self._db.execute(
                "DELETE FROM annotations WHERE sha256 = ? AND kind = 'name' AND address IS ?",
                (sha256, address),
            )
        elif kind == "verdict":
            self._db.execute(
                "DELETE FROM annotations WHERE sha256 = ? AND kind = 'verdict' AND target IS ?",
                (sha256, target),
            )
        try:
            cur = self._db.execute(
                "INSERT INTO annotations(sha256, kind, address, target, value, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (sha256, kind, address, target, value, time.time()),
            )
        except sqlite3.IntegrityError as exc:
            raise SessionError(f"unknown sample {sha256}") from exc
        return int(cur.lastrowid or 0)

    @_serialized
    def annotations(self, sha256: str, kind: str | None = None) -> list[Annotation]:
        query = (
            "SELECT id, sha256, kind, address, target, value, created_at FROM annotations "
            "WHERE sha256 = ?"
        )
        params: tuple[str, ...] = (sha256,)
        if kind is not None:
            query += " AND kind = ?"
            params += (kind,)
        rows = self._db.execute(query + " ORDER BY id", params).fetchall()
        return [Annotation(*r) for r in rows]

    @_serialized
    def delete_annotation(self, annotation_id: int) -> None:
        self._db.execute("DELETE FROM annotations WHERE id = ?", (annotation_id,))

    @_serialized
    def add_note(self, sha256: str, text: str, offset: int | None = None) -> int:
        """Backwards-compatible alias for a ``comment`` annotation."""
        return self.add_annotation(sha256, "comment", text, address=offset)

    @_serialized
    def notes(self, sha256: str) -> list[Note]:
        return [
            Note(a.id, a.sha256, a.address, a.value, a.created_at)
            for a in self.annotations(sha256, kind="comment")
        ]

    # -- carved payloads ---------------------------------------------------------------

    @_serialized
    def add_payload(self, parent_sha256: str, payload: Payload, data: bytes) -> None:
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO payloads(sha256, parent_sha256, offset, size, kind, "
                "location, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    payload.sha256,
                    parent_sha256,
                    payload.offset,
                    payload.size,
                    payload.kind,
                    payload.where,
                    data,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise SessionError(f"unknown sample {parent_sha256}") from exc

    @_serialized
    def payload_bytes(self, sha256: str) -> bytes | None:
        row = self._db.execute("SELECT data FROM payloads WHERE sha256 = ?", (sha256,)).fetchone()
        return bytes(row[0]) if row else None

    @_serialized
    def payloads(self, parent_sha256: str) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT sha256, offset, size, kind, location FROM payloads WHERE parent_sha256 = ? "
            "ORDER BY offset",
            (parent_sha256,),
        ).fetchall()
        return [
            {"sha256": s, "offset": o, "size": n, "kind": k, "where": w} for s, o, n, k, w in rows
        ]
