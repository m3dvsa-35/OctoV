from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from octov.app.api import ApiError, WorkbenchApi
from octov.core.analysis.pipeline import Pipeline
from octov.core.config import Config
from octov.core.static.pe_parser import parse_pe
from tests.samples.builder import DATA, TEXT, PESpec, SectionSpec, build_pe
from tests.unit.test_triage_api import _suspicious

ENTRY, MIDDLE, LEAF = 0x1000, 0x1010, 0x1020


def _chain_code(slot: int) -> bytes:
    # entry 0x1000: call middle; ret        middle 0x1010: call [CreateRemoteThread]; call leaf; ret
    # leaf 0x1020: mov eax, 0x1337; ret
    code = b"\xe8" + struct.pack("<i", MIDDLE - 0x1005) + b"\xc3"
    code = code.ljust(0x10, b"\xcc")
    code += b"\xff\x15" + struct.pack("<i", slot - 0x1016)
    code += b"\xe8" + struct.pack("<i", LEAF - 0x101B) + b"\xc3"
    code = code.ljust(0x20, b"\xcc")
    return code + b"\xb8\x37\x13\x00\x00\xc3"


def _chain(tmp_path: Path) -> Path:
    def build(slot: int) -> bytes:
        return build_pe(
            PESpec(
                sections=[
                    SectionSpec(".text", _chain_code(slot), TEXT),
                    SectionSpec(".data", b"\xde\xad\xbe\xef" + b"\x00" * 28, DATA),
                ],
                imports={"kernel32.dll": ["CreateRemoteThread", "GetTickCount"]},
                overlay=b"OVERLAY-DATA",
            )
        )

    slots = parse_pe(build(0)).import_addresses
    slot = next(rva for rva, name in slots.items() if name.endswith("CreateRemoteThread"))
    path = tmp_path / "chain.exe"
    path.write_bytes(build(slot))
    return path


def _api(tmp_path: Path) -> WorkbenchApi:
    return WorkbenchApi(Config(), settings_path=tmp_path / "ui.json", workspace_dir=tmp_path / "ws")


def _open(api: WorkbenchApi, path: Path, **kwargs: Any) -> str:
    sha = str(api.open_sample(str(path), **kwargs)["sha256"])
    assert api._get(sha).pipeline.wait_slow(30)
    return sha


def test_relations_center_apis_and_score(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = _open(api, _chain(tmp_path))
    rel = api.get_relations(sha, MIDDLE)
    nodes = {n["start"]: n for n in rel["nodes"]}
    assert rel["center"] == MIDDLE and set(nodes) == {ENTRY, MIDDLE, LEAF}
    assert nodes[ENTRY]["role"] == "caller" and nodes[ENTRY]["is_entry"]
    assert nodes[LEAF]["role"] == "callee" and nodes[LEAF]["distance"] == 1
    assert nodes[MIDDLE]["role"] == "center"
    assert nodes[MIDDLE]["apis"] == [
        {"name": "CreateRemoteThread", "family": "thread_inject", "suspicious": True}
    ]
    assert nodes[LEAF]["apis"] == [] and nodes[LEAF]["score"] == 0
    assert nodes[MIDDLE]["score"] > 0  # ranked: it calls an injection API
    assert sorted((e["src"], e["dst"]) for e in rel["edges"]) == [(ENTRY, MIDDLE), (MIDDLE, LEAF)]
    assert rel["path"] == [ENTRY, MIDDLE] and rel["truncated"] is False
    assert nodes[MIDDLE]["name"] == api.get_function(sha, MIDDLE)["name"]
    assert api.get_relations(sha, LEAF)["path"] == [ENTRY, MIDDLE, LEAF]
    assert api.get_relations(sha, ENTRY)["path"] == []


def test_relations_use_the_analysts_names(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = _open(api, _chain(tmp_path))
    api.annotate(sha, "name", "start_thread", address=MIDDLE)
    names = {n["start"]: n["name"] for n in api.get_relations(sha, ENTRY)["nodes"]}
    assert names[MIDDLE] == "start_thread" and names[LEAF] == f"sub_{LEAF:x}"


def test_relations_depth_is_clamped(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = _open(api, _chain(tmp_path))
    near = api.get_relations(sha, ENTRY, 1, 1)
    assert {n["start"] for n in near["nodes"]} == {ENTRY, MIDDLE}
    assert next(n for n in near["nodes"] if n["start"] == MIDDLE)["hidden_callees"] == 1
    assert {n["start"] for n in api.get_relations(sha, ENTRY, 0, 0)["nodes"]} == {ENTRY, MIDDLE}
    assert len(api.get_relations(sha, ENTRY, 99, 99)["nodes"]) == 3


def test_relations_unknown_start(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = _open(api, _chain(tmp_path))
    with pytest.raises(ApiError, match="no function at 0x1004"):
        api.get_relations(sha, 0x1004)


def test_relations_before_discovery_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Pipeline, "start_slow", lambda self, ctx, on_done=None: None)
    api = _api(tmp_path)
    sha = api.open_sample(str(_chain(tmp_path)))["sha256"]
    for call in (
        lambda: api.get_relations(sha, ENTRY),
        lambda: api.search(sha, "text", "mov"),
        lambda: api.search(sha, "imm", "0x1337"),
    ):
        with pytest.raises(ApiError, match=r"^analysis\.not_ready$"):
            call()
    assert (
        api.search(sha, "bytes", "b8 37 13")["items"][0]["function"] is None
    )  # bytes need no code
    assert api.get_symbols(sha)["imports"][0]["functions"][0]["refs"] == 0


def test_search_bytes_maps_offsets_to_rvas(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = _open(api, _chain(tmp_path))
    out = api.search(sha, "bytes", "B8 37 ?? 00")
    assert out["truncated"] is False and len(out["items"]) == 1
    hit = out["items"][0]
    assert hit["rva"] == LEAF and hit["function"] == LEAF
    assert hit["function_name"] == f"sub_{LEAF:x}" and hit["text"] == "b8 37 13 00"
    assert api.read_bytes(sha, hit["offset"], 4)["data"] == "uDcTAA=="
    overlay = api.search(sha, "bytes", "4f 56 45 52 4c 41 59")["items"]  # "OVERLAY": not mapped
    assert len(overlay) == 1 and overlay[0]["rva"] is None and overlay[0]["function"] is None
    header = api.search(sha, "bytes", "4d 5a")["items"][0]
    assert header["offset"] == 0 and header["rva"] is None
    assert api.search(sha, "bytes", "cc", 3)["truncated"] is True


def test_search_text_and_value(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = _open(api, _chain(tmp_path))
    text = api.search(sha, "text", "createremotethread")["items"]
    assert [h["rva"] for h in text] == [MIDDLE] and text[0]["function"] == MIDDLE
    assert "CreateRemoteThread" in text[0]["text"]
    value = api.search(sha, "imm", "1337h")["items"]
    assert [h["rva"] for h in value] == [LEAF] and value[0]["text"] == "mov eax, 0x1337"
    assert value[0]["offset"] == api.locate(sha, LEAF)["offset"]
    assert api.search(sha, "imm", "0x7777")["items"] == []


@pytest.mark.parametrize(
    ("kind", "query", "error"),
    [
        ("bytes", "zz", "search.bad_pattern"),
        ("bytes", "?? ??", "search.bad_pattern"),
        ("bytes", "", "search.bad_pattern"),
        ("imm", "twelve", "search.bad_number"),
        ("regex", "x", "unknown search kind 'regex'"),
    ],
)
def test_search_bad_input_is_api_error(kind: str, query: str, error: str, tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = _open(api, _chain(tmp_path))
    with pytest.raises(ApiError) as err:
        api.search(sha, kind, query)
    assert str(err.value) == error


def test_symbols_group_imports_by_dll_with_refs(tmp_path: Path) -> None:
    api = _api(tmp_path)
    sha = _open(api, _suspicious(tmp_path))
    symbols = api.get_symbols(sha)
    assert [g["dll"] for g in symbols["imports"]] == ["kernel32.dll"]
    funcs = {f["name"]: f for f in symbols["imports"][0]["functions"]}
    assert list(funcs) == ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"]
    assert funcs["CreateRemoteThread"]["refs"] == 1 and funcs["VirtualAllocEx"]["refs"] == 0
    slot = funcs["WriteProcessMemory"]["rva"]
    assert [x["func"] for x in api.xrefs_to(sha, slot)] == [0x1000]
    assert symbols["exports"] == []


def test_memory_map_regions_in_file_order(tmp_path: Path) -> None:
    api = _api(tmp_path)
    path = _chain(tmp_path)
    sha = _open(api, path)
    mm = api.get_memory_map(sha)
    regions = mm["regions"]
    assert mm["size"] == path.stat().st_size
    assert regions[0]["kind"] == "headers" and regions[0]["offset"] == 0
    assert regions[-1]["kind"] == "overlay" and regions[-1]["size"] == len(b"OVERLAY-DATA")
    assert regions[-1]["rva"] is None
    sections = [r for r in regions if r["kind"] == "section"]
    assert [r["name"] for r in sections][:2] == [".text", ".data"]
    assert sections[0]["rva"] == 0x1000 and sections[0]["perm"] == "R-X"
    assert sections[1]["perm"] == "RW-" and 0 <= sections[0]["entropy"] <= 8
    offsets = [r["offset"] for r in regions]
    assert offsets == sorted(offsets)
    assert sum(r["size"] for r in regions) == mm["size"]  # nothing counted twice or left out


def test_raw_sample_answers_everything(tmp_path: Path) -> None:
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\xe8\x0b\x00\x00\x00\xc3".ljust(0x10, b"\xcc") + b"\xb8\x37\x13\x00\x00\xc3")
    api = _api(tmp_path)
    sha = _open(api, blob, raw=True)
    rel = api.get_relations(sha, 0)
    assert {n["start"] for n in rel["nodes"]} == {0, 0x10} and rel["path"] == []
    assert api.search(sha, "bytes", "b8 37 13")["items"][0]["rva"] == 0x10
    assert [h["rva"] for h in api.search(sha, "imm", "0x1337")["items"]] == [0x10]
    assert api.get_symbols(sha) == {"imports": [], "exports": []}
    mm = api.get_memory_map(sha)
    assert [r["kind"] for r in mm["regions"]] == ["raw"] and mm["regions"][0]["size"] == mm["size"]
