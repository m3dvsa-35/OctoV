# Assisted Triage Core (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opening a sample produces an explained, evidence-backed triage report (risk score + reasons, capabilities, IOCs, packer verdict, embedded payloads, ranked functions, ATT&CK) that the analyst can correct, in both the desktop UI and the CLI.

**Architecture:** A new `octov.core.analysis` package holds a fact model and an analyzer pipeline; existing indicators/rules/discovery become analyzers. Fast analyzers run inside `open_sample`; slow ones run in a per-sample background queue with per-analyzer status. `WorkbenchApi` exposes the triage report, strings, IOCs, xrefs and annotations; the React UI adds a Triage tab, Strings tab, xref popover and annotation actions.

**Tech Stack:** Python 3.11+ (pefile, capstone, numpy, msgpack, pyzipper — new, pure Python), React 19 + TypeScript, vitest, pytest.

**Spec:** `docs/superpowers/specs/2026-11-08-assisted-analysis-design.md` (§5, §6 Phase 1, §7, §9).

## Global Constraints

- Local-only/offline; never write a carved executable to disk unencrypted; payload export = AES ZIP, password `infected`.
- Every fact has ≥ 1 evidence item with an offset or RVA (test-enforced; location-less facts carry the string value as `detail` *and* its offset).
- Fact ID = `<kind>:<source_id>:<primary>`; primary = lowest evidence RVA, else lowest offset, else first evidence `value` — written in hex for numbers (`0x1a2b`).
- Risk score: weights high 30 / medium 12 / low 4 / info 0, × confidence, sum capped at 100; bands 0–29 low, 30–59 medium, 60–100 high; false_positive/benign verdicts contribute 0.
- System32 baseline: 0 high facts and ≥ 95 % of binaries score *low*.
- Fast analyzers < 3 s for a 5 MB sample on the dev machine.
- New UI text in both `en.py` and `az.py` (`test_web_strings.py` enforces); never meaning by colour alone.
- Session schema v1 → v2 migration on open; `notes` rows migrate to `comment` annotations.
- Raw (non-PE) input: strings/IOCs, crypto, code xrefs, ranking, score work; PE-only analyzers report `unavailable`.
- ruff (line 100), mypy strict, TDD, Conventional Commits with the Co-Authored-By trailer.

## Review Focus

1. **Huge string counts** (a 10 MB resource-heavy binary yields > 100k strings) — UI must page/virtualise and the API must cap per call; test: `get_strings` with `limit`/`offset` returns ≤ limit and a total.
2. **Re-analysis after rule changes** — a verdict whose fact vanished must surface as orphaned, not disappear; test in Task 9.
3. **Malformed/truncated embedded PE** (MZ at end of file, bogus `e_lfanew`) — carving must skip silently, never raise; test in Task 6.
4. **Opening the same sample twice / from a session** — annotations must not duplicate and workspace auto-session must not be created twice; test in Task 9.
5. **IOC false positives from version strings** (`1.2.3.4` in `FileVersion`, `kernel32.dll` as a "domain") — classifier must reject them; tests in Task 2.

---

## File Structure

```
src/octov/core/analysis/
  __init__.py
  facts.py        Fact, Evidence, fact_id, adapters from indicators/findings
  pipeline.py     AnalysisContext, Analyzer protocol, Pipeline (fast + slow queue, status)
  strings.py      extract_strings, classify, FoundString
  iocs.py         Ioc, build_iocs, iocs_csv, iocs_json
  xrefs.py        Xref, XrefIndex
  crypto.py       CRYPTO_SIGNATURES, find_crypto
  carve.py        Payload, carve_payloads, payload_zip
  packer.py       PackerVerdict, packer_verdict
  naming.py       API_FAMILIES, suggest_name
  scoring.py      RankedFunction, rank_functions, RiskScore, risk_score
  report.py       build_triage (shared by API and CLI)
  analyzers.py    concrete Analyzer classes wiring the modules above
src/octov/core/static/disasm.py     + Instruction.data_ref
src/octov/core/session/session.py   schema v2, annotations, payloads, migration
src/octov/app/api.py                pipeline integration + new methods
src/octov/cli/main.py               `octov triage`
src/octov/core/i18n/{en,az}.py      fact explanations + UI strings
web/src/components/TriageView.tsx, StringsView.tsx, XrefPopover.tsx, AnnotateMenu.tsx
web/src/state/store.ts, api/client.ts, api/types.ts   new calls/state
tests/unit/test_analysis_*.py, test_session_v2.py, test_triage_api.py, test_triage_cli.py
tests/samples/builder.py            + resources/overlay helpers (embedded PE fixtures)
```

---

### Task 1: Fact model and analyzer pipeline

**Files:** Create `src/octov/core/analysis/{__init__,facts,pipeline}.py`; Test `tests/unit/test_analysis_pipeline.py`

**Interfaces:**
- Produces:
  - `Evidence(detail: str, offset: int | None = None, rva: int | None = None, type: str | None = None, value: str | None = None)` (frozen)
  - `Fact(kind: str, source_id: str, severity: Severity, title: str, evidence: tuple[Evidence, ...], mitre: tuple[str, ...] = (), tags: tuple[str, ...] = (), confidence: float = 1.0, explain_key: str | None = None)` with `.id -> str` and `.to_dict() -> dict[str, Any]`
  - `facts_from_indicators(report: PEReport) -> list[Fact]` (kind `indicator`, source_id = indicator id, explain_key `ind.<id>`)
  - `facts_from_findings(findings: list[Finding]) -> list[Fact]` (kind `rule`, source_id = rule id, explain_key `fact.rule`)
  - `AnalysisContext` dataclass: `data: bytes, report: PEReport | None, bits: int, findings: list[Finding], functions: dict[int, Function], index: FunctionIndex | None, results: dict[str, Any], facts: list[Fact]` + `add(facts: Iterable[Fact])` (dedupe by id)
  - `Analyzer` Protocol: `id: str, cost: Literal["fast","slow"], depends_on: tuple[str, ...], pe_only: bool, run(ctx) -> None`
  - `AnalyzerStatus = Literal["queued","running","done","failed","unavailable"]`
  - `Pipeline(analyzers: Sequence[Analyzer])`: `run_fast(ctx) -> None`, `start_slow(ctx, on_done: Callable[[], None]) -> None`, `status() -> dict[str, dict[str, Any]]` (`{"state", "error"}` per analyzer id)

- [ ] **Step 1: Tests** — `test_fact_id_uses_lowest_rva` (`Fact(kind="rule", source_id="EVA-001", evidence=(Evidence("a", rva=0x2010), Evidence("b", rva=0x2000)))` → `.id == "rule:EVA-001:0x2000"`); `test_fact_id_falls_back_to_offset_then_value`; `test_indicator_and_finding_adapters` (synthetic injector PE → kinds `indicator`/`rule`, every fact has evidence with offset or rva — for indicators without a location use `section.raw_offset` or offset 0 of the header and say so in `detail`); `test_pipeline_runs_fast_in_dependency_order`; `test_slow_analyzers_report_status_and_errors` (an analyzer raising → `failed` with message, others still `done`); `test_pe_only_analyzer_unavailable_for_raw`.
- [ ] **Step 2:** Run `pytest tests/unit/test_analysis_pipeline.py -q` → FAIL (module missing).
- [ ] **Step 3:** Implement. Topological order by `depends_on`; slow analyzers run sequentially in one daemon thread per sample; `status()` thread-safe.
- [ ] **Step 4:** Run tests → PASS. **Step 5:** Commit `feat(analysis): add fact model and analyzer pipeline`.

### Task 2: Strings extraction and classification

**Files:** Create `src/octov/core/analysis/strings.py`; Test `tests/unit/test_analysis_strings.py`

**Interfaces:**
- Produces: `FoundString(value: str, encoding: Literal["ascii","utf16"], offset: int, rva: int | None, section: str | None, category: str | None)`; `extract_strings(data: bytes, report: PEReport | None, min_len: int = 4) -> list[FoundString]` (sorted by offset); `classify(value: str) -> str | None` with categories `url, ipv4, ipv6, domain, email, registry, path, mutex, user_agent, base64, command, wallet`; `MAX_STRINGS = 200_000`.

- [ ] **Step 1: Tests** — parametrised `classify`: `"http://x.example/gate.php"→url`, `"185.23.10.4"→ipv4`, `"1.2.3.4"` inside `"FileVersion 1.2.3.4"`→`None` (only whole-string IPs; reject when all octets < 10 *and* the string came from a VERSIONINFO block — implement as: reject dotted quads where every octet ≤ 9), `"kernel32.dll"→None` (file names with PE extensions are never domains), `"evil-c2.top"→domain`, `"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"→registry`, `"C:\\Users\\Public\\a.exe"→path`, `"Global\\mtx_8812"→mutex`, `"Mozilla/5.0 (Windows NT 10.0)"→user_agent`, `"powershell -enc SQBFAFgA"→command`, `"bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"→wallet`, `"aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ="→base64`, `"Hello"→None`. `test_extract_ascii_and_utf16_with_offsets_and_rva` (builder PE with both encodings in `.data`); `test_extract_caps_count` (`MAX_STRINGS`); `test_raw_blob_strings_have_offsets_no_rva`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement with two compiled bytes regexes (printable ASCII runs; UTF-16LE runs) over the whole file; map offset→RVA via sections. **Step 4:** PASS. **Step 5:** Commit `feat(analysis): extract and classify strings`.

### Task 3: IOC list

**Files:** Create `src/octov/core/analysis/iocs.py`; Test `tests/unit/test_analysis_iocs.py`

**Interfaces:**
- Consumes: `FoundString` (Task 2).
- Produces: `Ioc(type: str, value: str, offsets: tuple[int, ...], benign_hint: str | None)`; `build_iocs(strings: Sequence[FoundString]) -> list[Ioc]` (types: url, ipv4, ipv6, domain, email, registry, mutex, path, user_agent, wallet, command); `iocs_csv(iocs) -> str` (header `type,value,offsets,benign_hint`); `iocs_json(iocs) -> str`.

- [ ] **Step 1: Tests** — dedupe same value at two offsets → one Ioc with both offsets; `10.0.0.5`, `127.0.0.1`, `192.168.1.1` → `benign_hint="private or reserved address"`; `microsoft.com`, `windowsupdate.com` subdomains → `benign_hint="well-known vendor domain"`; domain extracted from URL also listed as `domain`; CSV quoting of commas.
- [ ] **Step 2–4:** FAIL → implement (`ipaddress` module for reserved checks; small `BENIGN_DOMAINS` tuple) → PASS. **Step 5:** Commit `feat(analysis): derive IOC list from strings`.

### Task 4: Data references in the disassembler and the xref index

**Files:** Modify `src/octov/core/static/disasm.py` (Instruction + `_convert`); Create `src/octov/core/analysis/xrefs.py`; Test `tests/unit/test_analysis_xrefs.py`

**Interfaces:**
- Produces: `Instruction.data_ref: int | None` (RVA of a RIP-relative or absolute memory/immediate operand that lands inside the image, excluding branch targets); `Xref(src: int, dst: int, kind: Literal["call","jump","data","import"], func: int | None)`; `XrefIndex.build(functions: dict[int, Function], import_addresses: dict[int, str]) -> XrefIndex`; `.to(dst: int) -> list[Xref]`; `.from_function(start: int) -> list[Xref]`; `.imports_called(start: int) -> list[str]`.

- [ ] **Step 1: Tests** — `lea rcx, [rip + disp]` pointing at a string in `.data` → `data_ref` equals that RVA; `XrefIndex.to(string_rva)` contains `kind="data"` with `func` = containing function; call to helper → `kind="call"`; IAT call → `kind="import"` and `imports_called(fn)` lists `kernel32.dll!ExitProcess`; raw x64 blob xrefs work with `RawView`.
- [ ] **Step 2–4:** FAIL → implement (reuse `_RIP_SLOT`/`_ABS_SLOT`; `data_ref` only when `is_jump`/`is_call` is false) → PASS; rerun `tests/unit/test_disasm_cfg.py` (must stay green). **Step 5:** Commit `feat(analysis): add data references and xref index`.

### Task 5: Crypto and compression constants

**Files:** Create `src/octov/core/analysis/crypto.py`; Test `tests/unit/test_analysis_crypto.py`

**Interfaces:**
- Produces: `CryptoSig(name: str, family: str, pattern: bytes)`; `CRYPTO_SIGNATURES: tuple[CryptoSig, ...]` with at least: AES S-box `63 7c 77 7b f2 6b 6f c5`, AES Te0 `c6 63 63 a5 f8 7c 7c 84`, SHA-256 K `98 2f 8a 42 91 44 37 71`, MD5 T `78 a4 6a d7 56 b7 c7 e8`, CRC32 table `00 00 00 00 96 30 07 77`, Blowfish P `88 6a 3f 24 d3 08 a3 85`, ChaCha/Salsa `b"expand 32-byte k"`; `find_crypto(data: bytes, report: PEReport | None) -> list[Fact]` (kind `crypto_constant`, severity `low`, source_id = `name`, explain_key `fact.crypto_constant`, tags `(family,)`).

- [ ] **Step 1: Tests** — each signature planted in a synthetic `.rdata` is found once with correct offset/RVA; absent → none; same table twice → one fact with two evidence items.
- [ ] **Step 2–5:** FAIL → implement (`bytes.find` loop) → PASS → commit `feat(analysis): detect crypto constants`.

### Task 6: Embedded payload carving and safe export

**Files:** Create `src/octov/core/analysis/carve.py`; Modify `tests/samples/builder.py` (add `overlay`/resource helpers if needed); Modify `pyproject.toml` (+ `pyzipper>=0.3.6`); Test `tests/unit/test_analysis_carve.py`

**Interfaces:**
- Produces: `Payload(offset: int, size: int, kind: Literal["pe","high_entropy"], where: str, sha256: str)`; `carve_payloads(data: bytes, report: PEReport | None) -> list[Payload]` (MZ+valid `PE\0\0` at `e_lfanew` anywhere after offset 0; size = end of last section's raw data, capped at file end; `high_entropy` = resource blobs ≥ 4 KiB with entropy ≥ 7.2); `payload_zip(data: bytes, name: str) -> bytes` (AES-256 ZIP, password `infected`); fact kind `embedded_payload` (severity `medium` for `pe`, `low` for `high_entropy`).

- [ ] **Step 1: Tests** — builder PE with a second builder PE in the overlay → one `pe` payload at the right offset with correct size and sha256; MZ at last 2 bytes / bogus `e_lfanew` → no payload, no exception; `payload_zip` round-trips with `pyzipper` and fails without the password; raw blob containing a PE → carved.
- [ ] **Step 2–5:** FAIL → implement → PASS → commit `feat(analysis): carve embedded payloads with encrypted export`.

### Task 7: Packer verdict and auto-naming

**Files:** Create `src/octov/core/analysis/{packer,naming}.py`; Test `tests/unit/test_analysis_packer_naming.py`

**Interfaces:**
- Produces: `PackerVerdict(packed: bool, confidence: float, packer: str | None, reasons: tuple[str, ...])`; `packer_verdict(report: PEReport) -> PackerVerdict` (packed when ≥ 2 of: packer section name, entry section entropy ≥ 7.0, ≤ 10 imports with a resolver pair, RWX section, virtual-size-inflated section; `packer` from `PACKER_SECTION_NAMES`); fact kind `packer` (severity `medium`, emitted only when packed).
  `API_FAMILIES: dict[str, tuple[str, ...]]` with at least `net_http, net_socket, file_io, registry, process, thread_inject, crypto, service, mutex, anti_debug`; `suggest_name(start: int, imports_called: Sequence[str]) -> str | None` → `f"{family}_{start:x}"` when ≥ 2 calls belong to one family and it is ≥ 60 % of the function's import calls, else `None`.

- [ ] **Step 1: Tests** — UPX-like synthetic (UPX0/UPX1, RWX, 2 imports) → packed, packer `UPX`, ≥ 2 reasons; notepad-like (normal) → not packed; `suggest_name(0x401000, ["wininet.dll!InternetOpenA","wininet.dll!HttpSendRequestA","kernel32.dll!Sleep"]) == "net_http_401000"`; mixed families → `None`; A/W suffixes ignored (reuse `normalize_api`).
- [ ] **Step 2–5:** FAIL → implement → PASS → commit `feat(analysis): add packer verdict and API-based function names`.

### Task 8: Function ranking and risk score

**Files:** Create `src/octov/core/analysis/scoring.py`; Test `tests/unit/test_analysis_scoring.py`

**Interfaces:**
- Consumes: `Fact` (Task 1), `XrefIndex` (Task 4), `FoundString` (Task 2).
- Produces: `RankedFunction(start: int, name: str, score: int, reasons: tuple[str, ...])`; `rank_functions(functions, xrefs: XrefIndex, facts: Sequence[Fact], strings: Sequence[FoundString], names: Mapping[int, str]) -> list[RankedFunction]` (points: rule/indicator evidence inside the function 10×severity rank, suspicious API family call 5, IOC string referenced 4, crypto constant referenced 4; top 20, score > 0 only); `RiskScore(score: int, band: Literal["low","medium","high"], contributions: tuple[tuple[str, int], ...])`; `risk_score(facts: Sequence[Fact], verdicts: Mapping[str, str]) -> RiskScore` (Global Constraints weights).

- [ ] **Step 1: Tests** — 4 high facts → 100/high; 2 medium → 24/low; FP verdict on one high → its contribution 0 and listed with 0; confidence 0.5 halves points; ranking puts the function that references the injection APIs and a URL first with both reasons.
- [ ] **Step 2–5:** FAIL → implement → PASS → commit `feat(analysis): rank functions and compute transparent risk score`.

### Task 9: Session schema v2 — annotations, payloads, migration, workspaces

**Files:** Modify `src/octov/core/session/session.py`; Test `tests/unit/test_session_v2.py` (+ fixture `tests/samples/session_v1.octov` generated in the test from the v1 schema SQL)

**Interfaces:**
- Produces: `SCHEMA_VERSION = 2`; `Annotation(id: int, sha256: str, kind: Literal["name","comment","bookmark","verdict"], address: int | None, target: str | None, value: str, created_at: float)`; `Session.add_annotation(sha256, kind, value, address=None, target=None) -> int` (upsert for `name` per address and `verdict` per target; append for comment/bookmark); `Session.annotations(sha256, kind=None) -> list[Annotation]`; `Session.delete_annotation(annotation_id) -> None`; `Session.add_payload(parent_sha256, payload: Payload, data: bytes) -> None`; `Session.payload_bytes(child_sha256) -> bytes | None`; `Session.payloads(parent_sha256) -> list[dict[str, Any]]`. `notes`/`add_note` become thin wrappers over `comment` annotations.

- [ ] **Step 1: Tests** — v1 file with two notes opens, becomes v2, notes appear as comment annotations, old API `notes()` still returns them; second `name` on same address replaces the first; verdict upsert by `target`; payload round-trip; delete; v3 file still rejected.
- [ ] **Step 2–5:** FAIL → implement (migration in `Session.open` inside one transaction) → PASS → commit `feat(session): schema v2 with annotations, payloads and migration`.

### Task 10: Analyzers, API integration and triage report

**Files:** Create `src/octov/core/analysis/{analyzers,report}.py`; Modify `src/octov/app/api.py`; Test `tests/unit/test_triage_api.py` (and update `tests/unit/test_app_api.py` where `get_findings` shape changes)

**Interfaces:**
- Consumes: Tasks 1–9.
- Produces:
  - Analyzers (ids): `pe_indicators`(fast), `rules`(fast), `strings`(fast), `iocs`(fast, depends strings), `crypto`(fast), `carve`(fast), `packer`(fast, pe_only), `functions`(slow), `xrefs`(slow, depends functions), `naming`(slow, depends xrefs), `ranking`(slow, depends naming, strings, crypto).
  - `build_triage(ctx: AnalysisContext, verdicts: Mapping[str, str], names: Mapping[int, str]) -> dict[str, Any]` with keys `score{score,band,contributions[{fact_id,points,title}]}`, `packer{packed,confidence,packer,reasons}|None`, `capabilities[fact dicts of kind rule|indicator|crypto_constant|embedded_payload, verdict]`, `iocs[ioc dicts]`, `payloads[...]`, `top_functions[...]`, `attack[mitre rows]`, `orphaned_verdicts[{fact_id, verdict}]`, `jobs{analyzer_id: status}`.
  - `WorkbenchApi` new/changed methods: `get_triage(sha)`, `job_status(sha)` (replaces `discovery_status`, keep the old name as alias), `get_strings(sha, category: str | None = None, query: str = "", offset: int = 0, limit: int = 500) -> {"total", "items"}`, `get_iocs(sha)`, `export_iocs(sha, fmt: Literal["csv","json"]) -> str`, `xrefs_to(sha, rva)`, `annotate(sha, kind, value, address: int | None = None, target: str | None = None) -> dict`, `delete_annotation(sha, annotation_id)`, `list_annotations(sha)`, `set_verdict(sha, fact_id, verdict: Literal["false_positive","benign","confirmed"] | None)`, `list_payloads(sha)`, `open_payload(sha, payload_sha)` (opens carved bytes as a new in-memory sample with `parent` set), `export_payload(sha, payload_sha, path)` (AES ZIP only). `get_findings` now returns fact dicts (+ `verdict`), `list_functions`/`get_function` apply `name` annotations then suggested names (`suggested: true`). Exports (`export_yara`, `export_sigma`, `export_iocs`) skip facts with FP/benign verdicts. Annotation calls auto-create the workspace session under `workspace_dir` (constructor param, default `~/.octov/workspaces`) when none is open, at most once per sample.

- [ ] **Step 1: Tests** — `get_triage` on a synthetic sample with injection APIs + URL + AES S-box + overlay PE has score > 0, a contribution per fact, IOC `url`, payload listed, crypto capability, `top_functions[0]` reasons; after `set_verdict(fact, "false_positive")` the score drops and YARA omits that rule's strings; rename via `annotate(kind="name")` shows in `list_functions`; annotation without session creates exactly one workspace file; reopening the sample keeps annotations; orphaned verdict reported after removing a rule from config; `get_strings(limit=10)` → ≤ 10 items + total; raw blob triage: packer `None`, jobs `packer: unavailable`; every fact in `get_triage` has evidence with offset or rva (Global Constraint).
- [ ] **Step 2–5:** FAIL → implement → PASS (whole suite) → commit `feat(app): run analyzer pipeline and serve triage report`.

### Task 11: CLI `octov triage`

**Files:** Modify `src/octov/cli/main.py`; Test `tests/unit/test_triage_cli.py`

**Interfaces:** Consumes `build_triage` (Task 10). Produces `octov triage <file> [--raw] [--bits 32|64] [--json | --md] [--iocs out.csv] [--config]`; default output = readable text (score + band, top reasons, packer, capabilities, IOCs, top functions with RVA).

- [ ] **Step 1: Tests** — `--json` has keys of `build_triage`; `--md` starts with `# Triage:`; `--iocs` writes CSV with header; non-PE without `--raw` exits 2 with the `--raw` hint.
- [ ] **Step 2–5:** FAIL → implement (wait for slow analyzers synchronously in CLI) → PASS → commit `feat(cli): add triage command`.

### Task 12: Explanations (EN/AZ)

**Files:** Modify `src/octov/core/i18n/{en,az}.py`; Test `tests/unit/test_fact_explanations.py`

**Interfaces:** Keys `fact.<kind>.explain` and `fact.<kind>.next` for kinds `rule, indicator, crypto_constant, embedded_payload, packer, ioc`, plus `ind.<indicator_id>.explain` for every indicator id emitted by `pe_parser`; each explanation states what it is, why attackers use it, a benign reason, what to check next (2–4 sentences).

- [ ] **Step 1: Test** — every `explain_key` produced by analyzers on the synthetic corpus and every indicator id exists in both languages; no AZ string equals its EN string (catches untranslated copies) except proper nouns list.
- [ ] **Step 2–5:** FAIL → write texts → PASS → commit `feat(i18n): explain every fact kind in EN and AZ`.

### Task 13: Web UI — Triage, Strings, xrefs, annotations, compact mode

**Files:** Create `web/src/components/{TriageView,StringsView,XrefPopover,AnnotateMenu}.tsx`; Modify `web/src/{App.tsx,state/store.ts,api/client.ts,api/types.ts}`, `web/src/components/{FindingsView,DisasmView,Sidebar,TopBar,GraphView}.tsx`; Test `web/src/lib/triage.test.ts` (pure helpers), manual desktop check.

**Interfaces:** Consumes the Task 10 API. UI behaviour:
- Main tabs become `Triage | Overview | Disassembly | Graph | Hex | Strings`; Triage is the default after opening a sample.
- Triage: score gauge (number + band word + bar), contributions list (each with points, jump, verdict buttons ✓ confirm / ✗ false positive / benign), packer card with reasons, capability cards with explanation (collapsible), IOC table with copy/export CSV, payload list with "open as sample" and "export (encrypted ZIP)", top functions with jump-to-graph, job progress chips per analyzer.
- Strings: virtualised table with category filter chips, search, xref count; double-click → xref popover → jump.
- Disasm/graph: right-click or `n` = rename function, `;` = comment, `b` = bookmark; renamed names show everywhere; suggested names shown italic with "suggested".
- TopBar: `Compact` toggle (hides explanations), persisted in settings (`compact: bool` added to `get_settings`/`set_settings`).

- [ ] **Step 1:** vitest for `formatScoreBand`, `groupContributions`, `filterStrings` helpers → FAIL. **Step 2:** implement helpers → PASS. **Step 3:** build components; `npm run typecheck`, `npm test`, `npm run build` clean; `pytest tests/unit/test_web_strings.py` green. **Step 4:** manual check in the desktop window on notepad.exe and on a synthetic suspicious sample (both languages, both display modes): screenshot Triage, Strings, rename, verdict. **Step 5:** Commit `feat(ui): add triage, strings, xrefs and annotations`.

### Task 14: Baseline, performance and docs

**Files:** Modify `tests/unit/test_baseline_fp.py`; Create `tests/unit/test_triage_perf.py`; Modify `CLAUDE.md`, `README.md`

- [ ] **Step 1: Tests** — baseline now runs the full pipeline (fast + slow) on the System32 slice: 0 high facts, ≥ 95 % `band == "low"`; perf: synthetic 5 MB PE fast analyzers < 3 s.
- [ ] **Step 2:** Run full sweep `OCTOV_FULL_BASELINE=1` once and tune weights/heuristics if needed (record numbers in CLAUDE.md).
- [ ] **Step 3:** Update CLAUDE.md status + layout and README (Triage section, `octov triage`).
- [ ] **Step 4:** Full verification: ruff, mypy, pytest, tsc, vitest, build. **Step 5:** Commit, push branch, open PR (base: `feat/web-ui` until #3/#4 merge).
