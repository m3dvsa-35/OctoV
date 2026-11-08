from __future__ import annotations

import io
import struct
import time
from pathlib import Path

import pytest
import pyzipper
import yaml

from octov.app.api import ApiError, WorkbenchApi
from octov.core.config import Config
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

AES_SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
URL = b"http://x.example/gate.php\x00"
INNER = build_pe(PESpec(imports={"kernel32.dll": ["ExitProcess"]}))
IMPORTS = {"kernel32.dll": ["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx"]}


def _code(iat: list[int]) -> bytes:
    # 0x1000: lea rcx,[rip->URL @0x2000]; call [IAT0]; call [IAT1]; ret
    out = bytes.fromhex("488D0D") + struct.pack("<i", 0x2000 - 0x1007)
    pc = 0x1007
    for slot in iat[:2]:
        out += bytes.fromhex("FF15") + struct.pack("<i", slot - (pc + 6))
        pc += 6
    return out + b"\xc3"


def _suspicious(tmp_path: Path) -> Path:
    def build(iat: list[int]) -> bytes:
        return build_pe(
            PESpec(
                sections=[
                    SectionSpec(".text", _code(iat), TEXT),
                    SectionSpec(".data", URL + b"\x00" * 6 + AES_SBOX, DATA),
                ],
                imports=IMPORTS,
                overlay=INNER,
            )
        )

    probe = build([0, 0])
    iat = sorted(parse_pe(probe).import_addresses)
    path = tmp_path / "evil.exe"
    path.write_bytes(build(iat))
    return path


def _api(tmp_path: Path, config: Config | None = None) -> WorkbenchApi:
    return WorkbenchApi(
        config or Config(), settings_path=tmp_path / "ui.json", workspace_dir=tmp_path / "ws"
    )


def _wait(api: WorkbenchApi, sha: str) -> None:
    end = time.monotonic() + 15
    while any(j["state"] in ("queued", "running") for j in api.job_status(sha).values()):
        assert time.monotonic() < end
        time.sleep(0.02)


def test_triage_report_contents(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    _wait(api, sha)
    tri = api.get_triage(sha)
    assert tri["score"]["score"] > 0 and tri["score"]["band"] in ("low", "medium", "high")
    assert tri["score"]["contributions"]
    kinds = {c["kind"] for c in tri["capabilities"]}
    assert {"indicator", "crypto_constant", "embedded_payload"} <= kinds
    assert any(i["type"] == "url" for i in tri["iocs"])
    assert tri["payloads"][0]["sha256"]
    assert tri["top_functions"][0]["start"] == 0x1000
    assert any("url" in r for r in tri["top_functions"][0]["reasons"])
    assert tri["jobs"]["ranking"]["state"] == "done"
    for cap in tri["capabilities"]:
        assert any(e["offset"] is not None or e["rva"] is not None for e in cap["evidence"])


def test_false_positive_verdict_lowers_score_and_yara(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    _wait(api, sha)
    before = api.get_triage(sha)
    fact = next(c for c in before["capabilities"] if c["source_id"] == "process_injection_apis")
    api.set_verdict(sha, fact["id"], "false_positive")
    after = api.get_triage(sha)
    assert after["score"]["score"] < before["score"]["score"]
    assert (
        next(c for c in after["capabilities"] if c["id"] == fact["id"])["verdict"]
        == "false_positive"
    )
    api.set_verdict(sha, fact["id"], None)
    assert api.get_triage(sha)["score"]["score"] == before["score"]["score"]


def test_rename_and_suggested_names(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    _wait(api, sha)
    fn = next(f for f in api.list_functions(sha) if f["start"] == 0x1000)
    assert fn["name"] == "thread_inject_1000" and fn["suggested"] is True
    api.annotate(sha, "name", "inject_payload", address=0x1000)
    fn = next(f for f in api.list_functions(sha) if f["start"] == 0x1000)
    assert (fn["name"], fn["suggested"]) == ("inject_payload", False)
    assert api.get_function(sha, 0x1000)["name"] == "inject_payload"


def test_annotations_create_one_workspace_and_survive_reopen(tmp_path: Path) -> None:
    path = _suspicious(tmp_path)
    api = _api(tmp_path)
    sha = api.open_sample(str(path))["sha256"]
    api.annotate(sha, "comment", "look here", address=0x1000)
    api.annotate(sha, "bookmark", "entry", address=0x1000)
    assert len(list((tmp_path / "ws").glob("*.octov"))) == 1
    fresh = _api(tmp_path)
    fresh.open_sample(str(path))
    assert {a["kind"] for a in fresh.list_annotations(sha)} == {"comment", "bookmark"}
    fresh.open_sample(str(path))
    assert len(fresh.list_annotations(sha)) == 2


def test_orphaned_verdict_is_reported(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    api.set_verdict(sha, "rule:GONE-1:0x1000", "benign")
    assert {"fact_id": "rule:GONE-1:0x1000", "verdict": "benign"} in api.get_triage(sha)[
        "orphaned_verdicts"
    ]


def test_strings_are_paged_and_filtered(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    page = api.get_strings(sha, limit=2)
    assert page["total"] > 2 and len(page["items"]) == 2
    urls = api.get_strings(sha, category="url")
    assert [s["value"] for s in urls["items"]] == ["http://x.example/gate.php"]
    assert api.get_strings(sha, query="GATE")["total"] == 1


def test_iocs_xrefs_and_payload_export(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    _wait(api, sha)
    assert "x.example" in api.export_iocs(sha, "csv")
    [ref] = api.xrefs_to(sha, 0x2000)
    assert (ref["src"], ref["kind"], ref["func"]) == (0x1000, "data", 0x1000)
    [payload] = api.list_payloads(sha)
    out = tmp_path / "payload.zip"
    api.export_payload(sha, payload["sha256"], str(out))
    with pyzipper.AESZipFile(io.BytesIO(out.read_bytes())) as zf:
        zf.setpassword(b"infected")
        assert zf.read(zf.namelist()[0]) == INNER
    child = api.open_payload(sha, payload["sha256"])
    assert child["sha256"] == payload["sha256"] and child["format"] == "pe"
    with pytest.raises(ApiError):
        api.export_payload(sha, payload["sha256"], str(tmp_path / "payload.exe"))


def test_raw_blob_triage(tmp_path: Path) -> None:
    blob = tmp_path / "sc.bin"
    blob.write_bytes(bytes.fromhex("E80000000058") + b"\x90" * 4 + URL + b"\xc3")
    api = _api(tmp_path)
    sha = api.open_sample(str(blob), raw=True)["sha256"]
    _wait(api, sha)
    tri = api.get_triage(sha)
    assert tri["packer"] is None and tri["jobs"]["packer"]["state"] == "unavailable"
    assert any(i["type"] == "url" for i in tri["iocs"])


def test_get_findings_returns_facts_with_verdicts(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = api.open_sample(str(_suspicious(tmp_path)))["sha256"]
    rows = api.get_findings(sha)
    row = next(r for r in rows if r["source_id"] == "process_injection_apis")
    assert row["verdict"] is None and row["rva"] is not None and row["mitre_names"]["T1055"]


def test_orphan_after_rule_removed_from_config(tmp_path: Path) -> None:
    custom = tmp_path / "custom.yaml"
    rule = {
        "id": "CUST-1",
        "name": "marker",
        "description": "d",
        "severity": "low",
        "mitre": ["T1027"],
        "indicators": [{"type": "string", "value": "gate.php"}],
    }
    custom.write_text(yaml.safe_dump({"version": 1, "rules": [rule]}), encoding="utf-8")
    cfg = Config()
    cfg.rules.paths = [*cfg.rules.paths, custom]
    path = _suspicious(tmp_path)
    api = _api(tmp_path, cfg)
    sha = api.open_sample(str(path))["sha256"]
    fact = next(r for r in api.get_findings(sha) if r["source_id"] == "CUST-1")
    api.set_verdict(sha, fact["id"], "benign")
    plain = _api(tmp_path)
    plain.open_sample(str(path))
    assert fact["id"] in {o["fact_id"] for o in plain.get_triage(sha)["orphaned_verdicts"]}
