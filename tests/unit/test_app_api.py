"""Workbench API: the only contract between the web UI and the Python core."""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
import yara

from octov.app.api import ApiError, WorkbenchApi
from octov.app.devserver import make_server
from octov.core.config import Config
from octov.core.session.session import Session
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe

BRANCHY = bytes.fromhex("4885C97406B801000000C331C0E80E000000C3") + b"\xcc" * 13 + b"\xc3"
STUB = bytes.fromhex("4C8BD1B8180000000F05")


def _sample(tmp_path: Path, name: str = "s.exe", tag: bytes = b"") -> Path:
    path = tmp_path / name
    path.write_bytes(
        build_pe(
            PESpec(
                sections=[
                    SectionSpec(".text", BRANCHY, TEXT),
                    SectionSpec(".data", b"\x00" * 32 + STUB + tag, DATA),
                ],
                imports={"kernel32.dll": ["ExitProcess"]},
            )
        )
    )
    return path


@pytest.fixture
def api(tmp_path: Path) -> WorkbenchApi:
    return WorkbenchApi(Config(), settings_path=tmp_path / "ui.json")


def _wait_done(api: WorkbenchApi, sha: str) -> dict[str, object]:
    end = time.monotonic() + 10
    while True:
        status = api.discovery_status(sha)
        if status["state"] != "running":
            return status
        assert time.monotonic() < end
        time.sleep(0.02)


def test_open_sample_returns_summary(api: WorkbenchApi, tmp_path: Path) -> None:
    summary = api.open_sample(str(_sample(tmp_path)))
    assert summary["name"] == "s.exe"
    assert summary["format"] == "pe"
    assert len(summary["sha256"]) == 64
    assert summary["counts"]["high"] >= 1
    assert api.list_samples() == [summary]


def test_open_missing_or_invalid_file_raises_api_error(api: WorkbenchApi, tmp_path: Path) -> None:
    with pytest.raises(ApiError):
        api.open_sample(str(tmp_path / "missing.exe"))
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"not a pe")
    with pytest.raises(ApiError, match="raw"):
        api.open_sample(str(bad))


def test_overview_contains_headers_sections_and_imports(api: WorkbenchApi, tmp_path: Path) -> None:
    sha = api.open_sample(str(_sample(tmp_path)))["sha256"]
    ov = api.get_overview(sha)
    assert ov["machine"] == "AMD64" and ov["entry_point"] == 0x1000
    assert [s["name"] for s in ov["sections"]] == [".text", ".data", ".idata"]
    assert ov["sections"][0]["perm"] == "R-X"
    assert ov["imports"] == {"kernel32.dll": ["ExitProcess"]}


def test_findings_unify_indicators_and_rules_with_evidence(
    api: WorkbenchApi, tmp_path: Path
) -> None:
    sha = api.open_sample(str(_sample(tmp_path)))["sha256"]
    rows = api.get_findings(sha)
    rule = next(r for r in rows if r["source_id"] == "EVA-001")
    assert rule["kind"] == "rule" and rule["severity"] == "high"
    assert rule["rva"] == 0x2000 + 32
    assert rule["evidence"][0]["offset"] is not None
    assert rows[0]["severity"] == "high"  # sorted worst first
    assert all(r["mitre_names"] for r in rows if r["mitre"])


def test_mitre_aggregation(api: WorkbenchApi, tmp_path: Path) -> None:
    sha = api.open_sample(str(_sample(tmp_path)))["sha256"]
    rows = api.get_mitre(sha)
    t1106 = next(r for r in rows if r["technique"] == "T1106")
    assert t1106["name"] == "Native API" and "EVA-001" in t1106["sources"]


def test_functions_and_cfg(api: WorkbenchApi, tmp_path: Path) -> None:
    sha = api.open_sample(str(_sample(tmp_path)))["sha256"]
    assert _wait_done(api, sha)["state"] == "done"
    funcs = api.list_functions(sha)
    assert [f["start"] for f in funcs] == [0x1000, 0x1020]
    assert funcs[0]["is_entry"] is True
    fn = api.get_function(sha, 0x1000)
    assert {b["start"] for b in fn["blocks"]} == {0x1000, 0x1005, 0x100B}
    entry = next(b for b in fn["blocks"] if b["start"] == 0x1000)
    assert {(e["target"], e["kind"]) for e in entry["successors"]} == {
        (0x100B, "true"),
        (0x1005, "false"),
    }
    assert entry["instructions"][1]["target"] == 0x100B
    assert api.locate(sha, 0x1006) == {"rva": 0x1006, "offset": 0x406, "function": 0x1000}


def test_read_bytes_is_base64_chunk(api: WorkbenchApi, tmp_path: Path) -> None:
    path = _sample(tmp_path)
    sha = api.open_sample(str(path))["sha256"]
    chunk = api.read_bytes(sha, 0x400, 16)
    assert base64.b64decode(chunk["data"]) == path.read_bytes()[0x400:0x410]
    assert chunk["total"] == path.stat().st_size


def test_exports(api: WorkbenchApi, tmp_path: Path) -> None:
    path = _sample(tmp_path)
    sha = api.open_sample(str(path))["sha256"]
    assert yara.compile(source=api.export_yara(sha)).match(str(path))
    assert "Hashes|contains" in (api.export_sigma(sha) or "")


def test_raw_blob_mode(api: WorkbenchApi, tmp_path: Path) -> None:
    blob = tmp_path / "sc.bin"
    blob.write_bytes(bytes.fromhex("E80000000058") + b"\x90" * 4 + BRANCHY)
    summary = api.open_sample(str(blob), raw=True, bits=64)
    assert summary["format"] == "raw"
    sha = summary["sha256"]
    assert any(r["source_id"] == "PIC-003" for r in api.get_findings(sha))
    assert _wait_done(api, sha)["state"] == "done"
    assert api.list_functions(sha)[0]["start"] == 0
    assert api.export_sigma(sha) is None
    assert api.get_overview(sha)["format"] == "raw"


def test_unknown_sample_raises(api: WorkbenchApi) -> None:
    with pytest.raises(ApiError):
        api.get_overview("0" * 64)


def test_strings_and_settings_persist(api: WorkbenchApi, tmp_path: Path) -> None:
    assert api.strings("az")["menu.file"] == "Fayl"
    api.set_settings({"language": "az", "theme": "light"})
    again = WorkbenchApi(Config(), settings_path=tmp_path / "ui.json")
    assert again.get_settings() == {
        "language": "az",
        "theme": "light",
        "compact": False,
        "extensions_auto_run": {"capa": True, "floss": True, "ghidra": True},
    }
    with pytest.raises(ApiError):
        api.set_settings({"language": "xx"})


def test_compact_setting_persists(api: WorkbenchApi, tmp_path: Path) -> None:
    assert api.get_settings()["compact"] is False
    api.set_settings({"compact": True})
    again = WorkbenchApi(Config(), settings_path=tmp_path / "ui.json")
    assert again.get_settings()["compact"] is True
    with pytest.raises(ApiError):
        api.set_settings({"compact": "yes"})


def test_session_autosave_and_reopen(api: WorkbenchApi, tmp_path: Path) -> None:
    session_path = tmp_path / "case.octov"
    api.new_session(str(session_path))
    sample = _sample(tmp_path)
    sha = api.open_sample(str(sample))["sha256"]
    api.close_session()
    with Session.open(session_path) as s:
        assert s.get_sample(sha) is not None
    fresh = WorkbenchApi(Config(), settings_path=tmp_path / "ui2.json")
    listed = fresh.open_session(str(session_path))
    assert [x["sha256"] for x in listed] == [sha]


# --- dev server ------------------------------------------------------------------


@pytest.fixture
def server(api: WorkbenchApi, tmp_path: Path) -> Iterator[tuple[str, str]]:
    static = tmp_path / "dist"
    static.mkdir()
    (static / "index.html").write_text("<html>ok</html>", encoding="utf-8")
    srv, token = make_server(api, static_dir=static, port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", token
    srv.shutdown()


def _rpc(base: str, token: str | None, method: str, params: dict[str, object]) -> object:
    req = urllib.request.Request(
        f"{base}/rpc",
        data=json.dumps({"method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json", **({"X-OctoV-Token": token} if token else {})},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def test_devserver_requires_token(server: tuple[str, str]) -> None:
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _rpc(base, "wrong", "list_samples", {})
    assert exc.value.code == 401


def test_devserver_rpc_and_errors(server: tuple[str, str], tmp_path: Path) -> None:
    base, token = server
    out = _rpc(base, token, "open_sample", {"path": str(_sample(tmp_path))})
    assert isinstance(out, dict) and out["result"]["format"] == "pe"
    err = _rpc(base, token, "get_overview", {"sha": "0" * 64})
    assert isinstance(err, dict) and "error" in err
    with pytest.raises(urllib.error.HTTPError) as exc:
        _rpc(base, token, "_samples", {})
    assert exc.value.code == 404


def test_devserver_serves_static_and_blocks_traversal(server: tuple[str, str]) -> None:
    base, _ = server
    with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
        assert b"ok" in resp.read()
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{base}/..%2F..%2Fpyproject.toml", timeout=5)
    assert exc.value.code == 404


def test_browser_mode_has_no_native_dialogs(api: WorkbenchApi) -> None:
    assert api.capabilities() == {"native_dialogs": False}
    assert api.choose_file() is None
    assert api.choose_save_path("x.yar") is None


def test_save_text_writes_utf8(api: WorkbenchApi, tmp_path: Path) -> None:
    out = tmp_path / "rule.yar"
    api.save_text(str(out), "rule a { condition: true } // ə")
    assert out.read_text(encoding="utf-8").endswith("ə")
    with pytest.raises(ApiError):
        api.save_text(str(tmp_path / "missing-dir" / "x.yar"), "x")


def test_api_honours_configured_rule_paths(tmp_path: Path) -> None:
    import yaml

    custom = tmp_path / "custom.yaml"
    rule = {
        "id": "CUST-1",
        "name": "custom marker",
        "description": "d",
        "severity": "low",
        "mitre": ["T1027"],
        "indicators": [{"type": "string", "value": "octov-test-marker"}],
    }
    custom.write_text(yaml.safe_dump({"version": 1, "rules": [rule]}), encoding="utf-8")
    cfg = Config()
    cfg.rules.paths = [*cfg.rules.paths, custom]
    api = WorkbenchApi(cfg, settings_path=tmp_path / "ui.json")
    sha = api.open_sample(str(_sample(tmp_path, tag=b"octov-test-marker")))["sha256"]
    ids = {r["source_id"] for r in api.get_findings(sha)}
    assert {"CUST-1", "EVA-001"} <= ids


def test_devserver_reports_unexpected_errors(
    api: WorkbenchApi, server: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An internal bug must reach the UI as an error message, not an empty response."""

    def boom(sha: str) -> None:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(api, "_get", boom)  # rpc methods are bound at server start
    base, token = server
    with pytest.raises(urllib.error.HTTPError) as exc:
        _rpc(base, token, "get_overview", {"sha": "0" * 64})
    assert exc.value.code == 500
    assert "kaboom" in json.loads(exc.value.read())["error"]
