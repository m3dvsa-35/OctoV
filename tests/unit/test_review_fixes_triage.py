"""Regression tests for the Phase 1 final-review findings (Important 1-4)."""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

from octov.app.api import WorkbenchApi
from octov.core.analysis.iocs import build_iocs, ioc_fact_id
from octov.core.analysis.strings import FoundString, classify
from octov.core.config import Config
from tests.samples.builder import DATA, PESpec, SectionSpec, build_pe
from tests.unit.test_triage_api import _api, _suspicious, _wait


def _csv_values(text: str) -> set[str]:
    return {row["value"] for row in csv.DictReader(io.StringIO(text))}


# -- Important 1: verdicts reach the IOC and Sigma exports ---------------------------


def test_false_positive_ioc_is_dropped_from_exports(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    _wait(api, sha)
    row = next(i for i in api.get_triage(sha)["iocs"] if i["type"] == "domain")
    assert row["fact_id"] == f"ioc:domain:{hex(row['offsets'][0])}"
    assert row["verdict"] is None
    assert "x.example" in _csv_values(api.export_iocs(sha, "csv"))

    api.set_verdict(sha, row["fact_id"], "false_positive")

    assert "x.example" not in _csv_values(api.export_iocs(sha, "csv"))
    assert "x.example" not in {r["value"] for r in json.loads(api.export_iocs(sha, "json"))}
    again = next(i for i in api.get_triage(sha)["iocs"] if i["value"] == "x.example")
    assert again["verdict"] == "false_positive"  # still listed, so it can be undone


def test_ioc_rows_without_a_fact_have_no_fact_id(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    _wait(api, sha)
    facts = {f["id"] for f in api.get_findings(sha)}
    for row in api.get_triage(sha)["iocs"]:
        assert row["fact_id"] is None or row["fact_id"] in facts


def test_false_positive_indicator_is_dropped_from_sigma(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    plain_t1055 = re.compile(r"\bT1055\b(?!\.)")
    before = api.export_sigma(sha)
    assert before is not None and plain_t1055.search(before)
    fact = next(f for f in api.get_findings(sha) if f["source_id"] == "process_injection_apis")

    api.set_verdict(sha, fact["id"], "false_positive")

    after = api.export_sigma(sha)
    assert after is not None and not plain_t1055.search(after)


def test_ioc_fact_id_matches_analyzer_fact() -> None:
    iocs = build_iocs([FoundString("http://x.example/a", "ascii", 0x40, None, None, "url")])
    url = next(i for i in iocs if i.type == "url")
    assert ioc_fact_id(url) == "ioc:url:0x40"


# -- Important 2: workspace annotations follow the sample into a session ------------


def test_new_session_copies_workspace_annotations(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    _wait(api, sha)
    api.annotate(sha, "name", "inject_main", address=0x1000)
    fact = next(f for f in api.get_findings(sha) if f["source_id"] == "process_injection_apis")
    api.set_verdict(sha, fact["id"], "false_positive")
    score = api.get_triage(sha)["score"]["score"]

    session = tmp_path / "case.octov"
    api.new_session(str(session))

    kinds = sorted(a["kind"] for a in api.list_annotations(sha))
    assert kinds == ["name", "verdict"]
    assert api.get_triage(sha)["score"]["score"] == score
    api.close_session()

    fresh = WorkbenchApi(
        Config(), settings_path=tmp_path / "u2.json", workspace_dir=tmp_path / "w2"
    )
    fresh.open_session(str(session))
    assert sorted(a["kind"] for a in fresh.list_annotations(sha)) == ["name", "verdict"]


def test_open_session_merges_workspace_annotations_without_duplicates(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sample = _suspicious(tmp_path)
    sha = api.open_sample(str(sample))["sha256"]
    api.annotate(sha, "comment", "seen in workspace", address=0x1000)
    session = tmp_path / "case.octov"
    api.new_session(str(session))
    api.close_session()

    api.open_session(str(session))
    api.close_session()
    api.open_session(str(session))
    comments = [a for a in api.list_annotations(sha) if a["kind"] == "comment"]
    assert [c["value"] for c in comments] == ["seen in workspace"]


# -- Important 3: a malformed URL must not disable the IOC analyzer -----------------


def test_malformed_url_does_not_break_ioc_list() -> None:
    bad = "http://[x/gate"
    assert classify(bad) == "url"
    iocs = build_iocs(
        [
            FoundString(bad, "ascii", 0x10, None, None, "url"),
            FoundString("http://ok.example/a", "ascii", 0x40, None, None, "url"),
        ]
    )
    values = {(i.type, i.value) for i in iocs}
    assert ("url", bad) in values
    assert ("domain", "ok.example") in values


# -- Important 4: the triage payload caps the IOC list ------------------------------


def test_triage_caps_iocs_and_reports_total(tmp_path: Path) -> None:
    urls = b"".join(b"http://host%04d.example/p\x00" % i for i in range(300))
    path = tmp_path / "many.exe"
    path.write_bytes(build_pe(PESpec(sections=[SectionSpec(".data", urls, DATA)])))
    api = _api(tmp_path)
    sha = api.open_sample(str(path))["sha256"]
    _wait(api, sha)
    tri = api.get_triage(sha)
    assert tri["iocs_total"] == 600  # 300 URLs + 300 domains
    assert len(tri["iocs"]) == 200
    assert len(api.get_iocs(sha)) == 600
    assert len(_csv_values(api.export_iocs(sha, "csv"))) == 600
