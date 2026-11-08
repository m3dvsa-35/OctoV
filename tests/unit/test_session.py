from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from octov.core.session.session import Session, SessionError
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import build_pe

SHA = "a" * 64


def _report(sha: str = SHA) -> dict[str, object]:
    return {
        "path": "C:/x/evil.exe",
        "size": 1234,
        "hashes": {"sha256": sha},
        "nested": [1, {"k": b"\x00"}],
    }


def test_create_and_reopen_persists_samples(tmp_path: Path) -> None:
    path = tmp_path / "case.octov"
    with Session.create(path, name="Case 42") as s:
        s.add_sample(_report())

    with Session.open(path) as s:
        assert s.get_meta("name") == "Case 42"
        assert s.get_sample(SHA) == _report()
        [row] = s.list_samples()
        assert (row.sha256, row.path, row.size) == (SHA, "C:/x/evil.exe", 1234)


def test_accepts_pe_report_objects(tmp_path: Path) -> None:
    report = parse_pe(build_pe())
    with Session.create(tmp_path / "s.octov") as s:
        sha = s.add_sample(report)
        assert sha == report.hashes.sha256
        stored = s.get_sample(sha)
        assert stored is not None
        assert stored["sections"][0]["name"] == ".text"


def test_add_sample_twice_replaces_report(tmp_path: Path) -> None:
    with Session.create(tmp_path / "s.octov") as s:
        s.add_sample(_report())
        updated = {**_report(), "size": 99}
        s.add_sample(updated)
        assert len(s.list_samples()) == 1
        assert s.get_sample(SHA) == updated


def test_add_sample_requires_sha256(tmp_path: Path) -> None:
    with Session.create(tmp_path / "s.octov") as s, pytest.raises(SessionError):
        s.add_sample({"path": "x"})


def test_get_unknown_sample_returns_none(tmp_path: Path) -> None:
    with Session.create(tmp_path / "s.octov") as s:
        assert s.get_sample("f" * 64) is None


def test_exception_inside_context_rolls_back(tmp_path: Path) -> None:
    path = tmp_path / "s.octov"
    Session.create(path).close()
    with pytest.raises(RuntimeError), Session.open(path) as s:
        s.add_sample(_report())
        raise RuntimeError("boom")
    with Session.open(path) as s:
        assert s.list_samples() == []


def test_create_refuses_to_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "s.octov"
    Session.create(path).close()
    with pytest.raises(SessionError):
        Session.create(path)


def test_open_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(SessionError):
        Session.open(tmp_path / "missing.octov")


def test_open_foreign_sqlite_file_raises(tmp_path: Path) -> None:
    path = tmp_path / "other.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (x)")
    con.commit()
    con.close()
    with pytest.raises(SessionError):
        Session.open(path)


def test_artifacts_are_filtered_by_kind(tmp_path: Path) -> None:
    with Session.create(tmp_path / "s.octov") as s:
        s.add_sample(_report())
        s.add_artifact(SHA, "yara", {"rule": "rule a { condition: true }"})
        s.add_artifact(SHA, "ioc", {"type": "domain", "value": "example.invalid"})
        s.add_artifact(SHA, "yara", {"rule": "rule b { condition: false }"})

        yara = s.artifacts(SHA, kind="yara")
        assert [a.data["rule"][:6] for a in yara] == ["rule a", "rule b"]
        assert len(s.artifacts(SHA)) == 3


def test_artifact_for_unknown_sample_raises(tmp_path: Path) -> None:
    with Session.create(tmp_path / "s.octov") as s, pytest.raises(SessionError):
        s.add_artifact("b" * 64, "ioc", {})


def test_notes_keep_insertion_order_and_offsets(tmp_path: Path) -> None:
    with Session.create(tmp_path / "s.octov") as s:
        s.add_sample(_report())
        s.add_note(SHA, "entry stub", offset=0x1000)
        s.add_note(SHA, "general remark")
        notes = s.notes(SHA)
        assert [(n.text, n.offset) for n in notes] == [
            ("entry stub", 0x1000),
            ("general remark", None),
        ]


def test_meta_roundtrips_nested_values_and_default(tmp_path: Path) -> None:
    with Session.create(tmp_path / "s.octov") as s:
        s.set_meta("layout", {"docks": ["asm", "graph"], "zoom": 1.5})
        assert s.get_meta("layout") == {"docks": ["asm", "graph"], "zoom": 1.5}
        assert s.get_meta("absent", default=7) == 7


def test_closed_session_rejects_use(tmp_path: Path) -> None:
    s = Session.create(tmp_path / "s.octov")
    s.close()
    with pytest.raises(SessionError):
        s.list_samples()
