# Phase 3 Ghidra Decompiler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An optional Ghidra-backed Pseudo-C view per function, synced with disassembly/graph, with beginner guidance (marked lines, API explanations), fast after the first background analysis and cached.

**Architecture:** One long-lived pyghidra worker child process per open PE sample (Job Object isolation from Phase 2), JSON-lines protocol over stdin/stdout, background import + auto-analysis into a saved per-sample Ghidra project, on-demand decompilation with analyst names/comments applied in a rolled-back transaction, results cached per annotation hash.

**Tech Stack:** Python 3.12, pyghidra 3.2 + JPype (optional extra), Ghidra 12.x + JDK ≥ 21, ctypes Job Object, React/TS (virtualised view), pytest/vitest.

**Spec:** `docs/superpowers/specs/2026-11-10-decompiler-phase3-design.md` (parents: `2026-11-08-assisted-analysis-design.md`, `2026-11-09-assisted-triage-phase2-design.md`). Read CLAUDE.md first (mypy short path, `scripts/npm.py`, LF only, heredoc pitfalls).

## Global Constraints

- Extra: `ghidra = ["pyghidra>=3.2,<4"]`; never in the default dependency set; pyghidra/JPype are imported **only inside the worker process**, never in the OctoV process (probe with `importlib.util.find_spec`).
- Ghidra accepted: any `12.x` (from `Ghidra/application.properties`, key `application.version`); else reason `ext.reason.ghidra_version`.
- Pinned download: `ghidra_12.2_PUBLIC_20261016.zip`, 569,712,708 bytes, sha256 `2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67`, URL `https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip`, installed to `~/.octov/ghidra/12.2/`.
- JDK ≥ 21, discovery order: config `extensions.ghidra.java_home` → `JAVA_HOME` → newest under `C:\Program Files\{Eclipse Adoptium,Java,Microsoft,Zulu,Amazon Corretto}\` → `java` on PATH; version from the JDK `release` file (`JAVA_VERSION="…"`), never by running Java in the OctoV process.
- Config `extensions.ghidra`: `max_memory_mb: 4096`, `max_workers: 2`, `idle_minutes: 10`, `decompile_timeout_s: 30`, `analysis_timeout_s: 900`, `project_keep_days: 30`, `install_dir` (path, optional), `java_home` (path, optional).
- Only one first-time analysis at a time app-wide; at most `max_workers` workers alive; extra samples `queued`.
- Saved project `~/.octov/ghidra-projects/<sha256>/` stays exactly as auto-analysis left it; analyst names/comments applied per request in a rolled-back transaction.
- Sample bytes go to the worker over the pipe (base64), imported from memory; never written to disk as an executable; carved payloads supported; raw (non-PE) samples → `unavailable` (`ext.reason.pe_only`).
- Pseudo-C cache: `~/.octov/cache/<sha>/ghidra-<ghidra version>-<annotation hash>/<entry rva hex>.json.gz` (reuse `octov.ext.cache`); never in `.octov` sessions.
- Settings: `extensions_auto_run` gains `ghidra` (default true).
- Markers never by colour alone; every new UI string in `en.py` and `az.py`.
- Tests never need Ghidra (fake worker); real-Ghidra integration tests are skipped unless Ghidra + JDK + pyghidra are present.

## Review Focus

1. **Worker dies or hangs mid-request** (JVM OOM, Ghidra exception, stuck decompile): the request fails with a reason within its timeout, the worker restarts once, a second death marks `failed`; the UI never spins forever. Test in Task 4 (`test_worker_crash_restarts_once_then_fails`, `test_request_timeout_kills_worker`).
2. **Rename while a decompile is in flight / rename storm**: the result shown matches the latest annotations (stale results discarded by annotation hash). Test in Task 6 (`test_stale_annotation_result_is_not_cached_as_current`).
3. **Address not inside any Ghidra function** (data, padding, OctoV-only function): a clear "no function here" result, no exception. Test in Task 5 (`test_decompile_outside_function`).
4. **Sample closed while its worker is analysing, or app exit**: worker process terminated, analysis slot released, no orphan JVM. Test in Task 4 (`test_close_stops_worker_and_frees_slot`).
5. **Corrupt or half-written Ghidra project folder** (crash during save): the project is discarded and re-analysed instead of failing forever. Test in Task 3 (`test_corrupt_project_is_reanalysed`, fake worker reports `project_error`).

---

### Task 1: Ghidra config, extra, JDK and install discovery, status

**Files:**
- Modify: `pyproject.toml` (extra `ghidra`), `src/octov/core/config.py` (`GhidraConfig`, `Config.ghidra`, parse `extensions.ghidra`), `config.yaml.example`
- Create: `src/octov/ext/ghidra/__init__.py`, `src/octov/ext/ghidra/discover.py`
- Modify: `src/octov/ext/__init__.py` (`ALL_EXTENSIONS = (*ENGINES, "ghidra")`)
- Test: `tests/unit/test_ghidra_discover.py`, `tests/unit/test_config.py`

**Interfaces:**
- Produces: `GhidraConfig(max_memory_mb=4096, max_workers=2, idle_minutes=10, decompile_timeout_s=30, analysis_timeout_s=900, project_keep_days=30, install_dir: Path | None = None, java_home: Path | None = None)`; `Config.ghidra: GhidraConfig` (the `extensions.ghidra` YAML block; `Config.extensions` keeps capa/floss only).
- Produces: `java_version(home: Path) -> tuple[int, ...] | None` (reads `release`); `find_jdk(cfg: GhidraConfig, env: Mapping[str,str], roots: Sequence[Path] = DEFAULT_JDK_ROOTS, which=shutil.which) -> tuple[Path, str] | None` (home, version string; only ≥ 21); `ghidra_version(install: Path) -> str | None`; `find_ghidra(cfg, env, home_root: Path) -> Path | None` (config → `home_root/"ghidra"/<newest>` → `GHIDRA_INSTALL_DIR`).
- Produces: `ghidra_status(cfg, env=os.environ, home_root=Path.home()/".octov", finder=importlib.util.find_spec) -> ExtensionStatus` with `id="ghidra"`, `version` = Ghidra version, `rules_version` = JDK version string, reasons `ext.reason.not_installed` (no pyghidra), `ext.reason.no_ghidra`, `ext.reason.ghidra_version`, `ext.reason.no_jdk`; `install_cmd="python -m uv sync --extra ghidra"`, `setup_cmd="octov ext setup ghidra"`.

- [ ] **Step 1: Write failing tests** (fake trees in `tmp_path`): `test_java_version_from_release_file` (`JAVA_VERSION="25.0.1"` → `(25, 0, 1)`; `"1.8.0_401"` → `(1, 8, 0)`); `test_find_jdk_skips_old_java_home_and_finds_adoptium` (JAVA_HOME = Java 8 tree, root has `jdk-25.0.1.8-hotspot` → that one); `test_find_jdk_config_wins`; `test_no_jdk_21`; `test_ghidra_version_from_properties` (`application.version=12.2` → `"12.2"`); `test_status_reasons` (each reason in order: no pyghidra → not_installed; no install → no_ghidra; 11.4 → ghidra_version; no JDK → no_jdk; all present → ready); config: `extensions.ghidra.max_workers: 1` parsed, `extensions.ghidra.java_home: C:/x` → Path, unknown key → `ConfigError`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ghidra_discover.py tests/unit/test_config.py -q` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS. Then `python -m uv lock` + `python -m uv sync --all-extras`; confirm `find_spec("pyghidra")`.
- [ ] **Step 5: Commit** `feat(ghidra): config, JDK/Ghidra discovery and status`

### Task 2: `octov ext setup ghidra` and status listing

**Files:**
- Create: `src/octov/ext/ghidra/setup.py`
- Modify: `src/octov/cli/ext.py` (`setup ghidra`, ghidra line in `status`), `src/octov/ext/capa_rules.py` (extract the safe-zip helper to `src/octov/ext/archive.py` and reuse it)
- Test: `tests/unit/test_ghidra_setup.py`, `tests/unit/test_ext_cli.py`

**Interfaces:**
- Produces: `safe_extract(archive: Path, target: Path, strip_top: bool = True) -> None` in `octov/ext/archive.py` (raises `RulesError` on unsafe names; used by capa rules and Ghidra); `GHIDRA_VERSION="12.2"`, `GHIDRA_URL`, `GHIDRA_SIZE=569_712_708`, `GHIDRA_SHA256` (Global Constraints); `install_ghidra(home_root: Path, zip_path: Path | None = None, fetch=_download) -> Path` → `home_root/"ghidra"/"12.2"`.
- CLI: `octov ext setup ghidra [--from-zip PATH]` prints `downloading Ghidra 12.2 (543 MiB) from github.com/NationalSecurityAgency/ghidra` before fetching; `status` prints `ghidra ready (Ghidra 12.2, JDK 25.0.1)` or the reason with the command.

- [ ] **Step 1: Write failing tests:** `test_install_from_zip` (small fake zip with `ghidra_12.2_PUBLIC/Ghidra/application.properties`, pinned hash monkeypatched → installed dir has the properties file); `test_checksum_mismatch`; `test_zip_slip_rejected`; `test_capa_rules_still_install` (existing capa tests stay green after the helper move); CLI `test_setup_ghidra_prints_size_first` (fetch replaced, output order: size line before the installed line); `test_status_lists_ghidra` (status pinned via monkeypatch, as in the Phase 2 CI fix).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ghidra_setup.py tests/unit/test_ext_cli.py tests/unit/test_ext_capa_rules.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS. Then install for real on the dev machine: `.venv/Scripts/python -m octov.cli.main ext setup ghidra` (owner-approved design; ~570 MB) and `ext status` → ghidra ready.
- [ ] **Step 5: Commit** `feat(ghidra): pinned Ghidra setup and status`

### Task 3: Worker script and protocol (real Ghidra side)

**Files:**
- Create: `src/octov/ext/ghidra/worker.py` (runs **only** in the child: `python -m octov.ext.ghidra.worker`)
- Create: `tests/fixtures/fake_ghidra_worker.py` (same protocol, canned replies; modes `ok`, `slow`, `crash_on_decompile`, `hang`, `project_error`)
- Test: `tests/unit/test_ghidra_protocol.py`, `tests/unit/test_ghidra_integration.py` (skipped unless ready)

**Interfaces:**
- Protocol (one JSON object per line, UTF-8; every request has `id`, every reply echoes it):
  - `{"id","op":"open","sha256","data_b64","project_dir","analysis_timeout_s"}` → `{"id","ok":true,"analysed":bool,"seconds":float}` or `{"id","ok":false,"error":"project_error"|"import_error"|"timeout","detail"}`.
  - `{"id","op":"functions"}` → `{"id","ok":true,"functions":[[entry_rva, name], …]}`.
  - `{"id","op":"decompile","rva","names":{"<rva>":name},"comments":{"<rva>":text},"timeout_s"}` → `{"id","ok":true,"entry_rva","name","lines":[[text,[rva,…]],…],"warnings":[…]}` or `{"ok":false,"error":"no_function"|"decompile_failed"|"timeout","detail"}`.
  - `{"id","op":"shutdown"}` → process exits 0.
- Produces: `protocol.encode(obj) -> bytes`, `protocol.decode(line: bytes) -> dict` in `src/octov/ext/ghidra/protocol.py` (shared by worker and client).
- Worker behaviour: `pyghidra.start(install_dir=…)`; import from a byte provider (no temp executable), language by PE loader; open existing project if present (project_error → delete folder, re-import, report `analysed: true`); auto-analysis then save; decompile with `DecompInterface` in a transaction that applies names/comments and is rolled back; lines via `DecompilerUtils.toLines(markup)` with each line's token addresses as RVAs (minus image base).

- [ ] **Step 1: Write failing tests** for `protocol` round-trip and for the fake worker contract (spawn `[sys.executable, fake, mode]`, send `open` / `decompile` / `shutdown`, check replies): `test_protocol_round_trip`, `test_fake_worker_contract`. Integration (skipif): `test_real_ghidra_decompiles_synthetic_injector` (open `_suspicious` bytes → `functions` contains `0x1000`, `decompile 0x1000` lines contain `CreateRemoteThread` or the IAT call, with `0x1000`-range RVAs) and `test_real_ghidra_applies_names` (names `{"0x1000": "inject_main"}` → name in output; a second decompile without names shows Ghidra's default again: the rollback works).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ghidra_protocol.py tests/unit/test_ghidra_integration.py -q -rs` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement** the protocol module, fake worker, real worker. Verify the pyghidra / Ghidra 12 API calls interactively in the dev venv before writing them (byte-provider import, `DecompilerUtils.toLines`, transaction rollback).
- [ ] **Step 4: Run** — Expected: PASS (integration runs on the dev machine).
- [ ] **Step 5: Commit** `feat(ghidra): pyghidra worker and JSON-lines protocol`

### Task 4: Worker manager (lifecycle, limits, restart, idle)

**Files:**
- Modify: `src/octov/ext/runner.py` (extract `spawn_isolated(argv, max_memory_mb, env) -> IsolatedProcess` used by `run_engine`)
- Create: `src/octov/ext/ghidra/manager.py`
- Test: `tests/unit/test_ghidra_manager.py`, existing `tests/unit/test_ext_runner.py`

**Interfaces:**
- Produces: `IsolatedProcess` (stdin/stdout pipes, `kill()`, `alive()`, `pid`) from `spawn_isolated`; `run_engine` behaviour unchanged.
- Produces: `GhidraWorker(sha, data, cfg, command, project_root)` with `start() -> None` (spawn + `open`, raises `GhidraError(kind, reason)`), `request(op: dict, timeout_s: float) -> dict`, `stop()`; one in-flight request at a time (lock).
- Produces: `GhidraManager(cfg, command_factory, project_root, clock=time.monotonic)` with `ensure(sha, data, on_state) -> None` (queue + start; at most `max_workers`; one analysis at a time), `decompile(sha, rva, names, comments) -> dict`, `functions(sha) -> list[tuple[int,str]]`, `close(sha)`, `shutdown_all()`, `reap_idle()` (stops workers idle ≥ `idle_minutes`; `decompile` restarts them from the project). `on_state(state, error, elapsed_s)` reports `queued|running|done|failed`.
- Restart rule: worker death or request timeout → kill, restart once, retry the request once; second failure → `GhidraError("crash", …)` and state `failed`.
- `GhidraError(kind: Literal["crash","timeout","no_function","decompile_failed","project_error"], reason: str)`.
- Produces: `cleanup_projects(root: Path, keep_days: int, now: float) -> list[Path]` (deletes project folders whose last use, the folder's mtime touched on every `open`, is older than `keep_days`; called once at API start).

- [ ] **Step 1: Write failing tests** with the fake worker: `test_max_workers_queues_third`, `test_one_analysis_at_a_time` (`slow` mode: second sample's `open` starts only after the first finishes), `test_worker_crash_restarts_once_then_fails`, `test_request_timeout_kills_worker` (`hang` mode, timeout 1 s), `test_close_stops_worker_and_frees_slot`, `test_idle_worker_is_reaped_and_restarted` (fake clock), `test_cleanup_projects_keeps_recent` (two folders, mtimes 40 and 5 days old → only the old one deleted), runner: `test_spawn_isolated_memory_limit` (existing `alloc` fake engine through the new helper).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ghidra_manager.py tests/unit/test_ext_runner.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.** Worker command: `[sys.executable, "-m", "octov.ext.ghidra.worker", "--ghidra", install, "--max-heap-mb", str(max_memory_mb - 512)]` with env `JAVA_HOME` set (and `OCTOV_AI_KEY` removed from the child env).
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ghidra): worker manager with limits, restart and idle stop`

### Task 5: Decompiled model, line marks, cache

**Files:**
- Create: `src/octov/ext/ghidra/model.py`
- Test: `tests/unit/test_ghidra_model.py`

**Interfaces:**
- Consumes: Phase 1 `Fact`, `XrefIndex.imports_called`, `naming.API_FAMILIES`, `scoring.SUSPICIOUS_FAMILIES`; Phase 2 `ext.cache`.
- Produces: `Line(text: str, rvas: tuple[int, ...])`; `DecompiledFunction(entry_rva: int, name: str, lines: tuple[Line, ...], warnings: tuple[str, ...])` with `from_reply(reply: dict) -> DecompiledFunction` and `to_dict()`.
- Produces: `annotation_hash(names: Mapping[int,str], comments: Mapping[int,str]) -> str` (sha256 of the sorted JSON, first 16 hex).
- Produces: `line_marks(fn: DecompiledFunction, facts: Sequence[Fact], api_names: Mapping[str, str]) -> list[list[dict]]` — per line: `{"kind":"fact","fact_id","severity"}` when a line RVA is evidence of a fact (fact evidence rva ∈ line rvas), and `{"kind":"api","api","family"}` when the line text contains a call to an API whose family is in `SUSPICIOUS_FAMILIES` (word match on the API name with and without A/W suffix).
- Produces: `cache_path(cache_dir, sha, ghidra_version, ahash, entry_rva) -> Path`.

- [ ] **Step 1: Write failing tests:** `test_from_reply_maps_lines`; `test_annotation_hash_stable_and_order_free`; `test_fact_mark_on_evidence_line`; `test_api_mark_on_suspicious_call` (`CreateRemoteThread(...)` line → api mark, `GetTickCount()` → none); `test_decompile_outside_function` (reply `{"ok":false,"error":"no_function"}` → `GhidraError("no_function", …)` raised by `from_reply`); `test_cache_path_includes_hash`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ghidra_model.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ghidra): decompiled-function model, line marks and cache keys`

### Task 6: WorkbenchApi integration

**Files:**
- Modify: `src/octov/app/api.py`, `src/octov/ext/__init__.py` (status list includes ghidra)
- Test: `tests/unit/test_ghidra_api.py`

**Interfaces:**
- Consumes: Tasks 1, 4, 5.
- Produces API: `get_decompiled(sha: str, rva: int) -> dict` = `DecompiledFunction.to_dict()` + `"marks"` (per line) + `"octov_function": int | None` + `"cached": bool`; raises `ApiError` with the reason key for `no_function` / not ready / pe_only; `get_extensions()` includes ghidra; settings `extensions_auto_run.ghidra`.
- Behaviour: on `open_sample` of a PE with ghidra ready and auto-run on → `GhidraManager.ensure` (state in `job_status["ghidra"]`); raw → `unavailable` `ext.reason.pe_only`; after analysis `done`, pre-decompile the top 10 `ranking` functions into the cache (background); `close_sample` → `manager.close`; app exit → `shutdown_all`; `annotate`/`delete_annotation` of names/comments changes the annotation hash (old cache entries simply stop matching); `run_extension(sha, "ghidra", force)` re-analyses (deletes the project when `force`).
- Stale results: a decompile finished for an annotation hash that is no longer current is cached under its own hash but not returned as current.

- [ ] **Step 1: Write failing tests** with a fake manager (monkeypatched factory to the fake worker): `test_get_decompiled_returns_lines_marks_and_function`, `test_cache_hit_skips_worker`, `test_rename_changes_hash_and_redecompiles`, `test_stale_annotation_result_is_not_cached_as_current`, `test_raw_sample_pe_only`, `test_carved_payload_is_decompilable` (payload child → ensure called with its bytes), `test_close_sample_closes_worker`, `test_top_functions_predecompiled`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ghidra_api.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full suite (deselect the two System32 sweeps) — Expected: PASS.
- [ ] **Step 5: Commit** `feat(app): decompiled functions in the workbench API`

### Task 7: API explanations and reading guide (EN/AZ)

**Files:**
- Create: `src/octov/core/apidoc.py` (API → i18n key), Modify: `src/octov/core/i18n/{en,az}.py`
- Test: `tests/unit/test_apidoc.py`

**Interfaces:**
- Produces: `API_DOC: dict[str, str]` (normalised API name → key `api.<Name>`), `api_doc_keys() -> list[str]`; strings `api.<Name>` (one line each, "what it does; why malware uses it"), `decomp.help.title`, `decomp.help.body`, `decomp.no_function`, `decomp.analysing`, `decomp.mark.fact`, `decomp.mark.api`, `ext.reason.no_ghidra`, `ext.reason.ghidra_version`, `ext.reason.no_jdk`, `ext.reason.pe_only`, `ext.ghidra.adds`, `ui.pseudo_c`.
- Coverage rule: every API in `naming.API_FAMILIES` and every import name used by `rules/*.yaml` import conditions has an `api.*` key in EN and AZ (AZ ≠ EN).

- [ ] **Step 1: Write failing tests:** `test_every_family_api_documented`, `test_rule_imports_documented`, `test_az_translated`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_apidoc.py tests/unit/test_i18n.py -q` — Expected: FAIL.
- [ ] **Step 3: Write the table and strings** (Write tool / bytes; LF).
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(i18n): API explanations and pseudo-C reading guide`

### Task 8: Web UI — Pseudo-C view

**Files:**
- Modify: `web/src/api/{types,client}.ts`, `web/src/state/store.ts`, `web/src/App.tsx`, `web/src/components/TriageView.tsx`
- Create: `web/src/components/PseudoCView.tsx`, `web/src/lib/pseudoc.ts`
- Test: `web/src/lib/pseudoc.test.ts`, `tests/unit/test_web_strings.py`

**Interfaces:**
- Consumes: Task 6 API, Task 7 keys.
- Produces helpers: `linesForRva(lines, rva) -> number[]` (indexes of lines whose rvas contain the rva, or the nearest preceding line by first rva); `tokenize(text) -> {text, kind}[]` (keyword/type/number/string/comment/identifier/api via a small set; apis = names present in the API doc keys); `markLabel(mark, t) -> string`.
- Behaviour: new tab `pseudo_c` in main and side panels; virtualised lines; current nav rva lines highlighted; click → `navigate(firstRva, { view: current })`; gutter marker per line (icon + severity text, tooltip with fact title/explanation, click → finding); API hover → `t("api.<Name>")`; collapsible "How to read this" (hidden in Compact); analysing state with elapsed; engine card when Ghidra is missing; Triage top functions get a "Pseudo-C" jump; the view refetches when the function or the annotation set changes.

- [ ] **Step 1: Write failing vitest:** `linesForRva` (exact, nearest-preceding, none), `tokenize` (keyword, number, string, API), `markLabel`.
- [ ] **Step 2: Run** `.venv/Scripts/python scripts/npm.py test` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `scripts/npm.py test`, `run typecheck`, `run build`, `pytest tests/unit/test_web_strings.py` — Expected: all PASS. Manual desktop check (EN/Night, AZ/Normal) on the synthetic injector and notepad.exe with real Ghidra: analysing state, code shown, click-sync both ways, rename reflected, markers + API hover.
- [ ] **Step 5: Commit** `feat(ui): pseudo-C view with sync, markers and API help`

### Task 9: Speed check, docs, final verification

**Files:**
- Create: `scripts/ghidra_speed.py` (open N System32 PEs of different sizes with the real manager; prints analysis seconds, reopen seconds, decompile p50/p95, cached p50)
- Modify: `README.md` (Decompiler section), `CLAUDE.md` (status, layout `ext/ghidra/`, numbers, Phase 2 merged)
- Test: full gates

- [ ] **Step 1: Run** `scripts/ghidra_speed.py` on 6 PEs (small → ~20 MB) and record the numbers; check the spec budget (decompile ≤ 1 s typical, cached ≤ 50 ms, reopen ≤ 15 s for 5 MB). If a budget fails, tune timeouts/limits within the spec ranges and note it as a ruling.
- [ ] **Step 2: Docs** — README Decompiler section (what it adds, `uv sync --extra ghidra`, `octov ext setup ghidra`, JDK note), CLAUDE.md status/layout/numbers.
- [ ] **Step 3: Full verification:** ruff format + check, mypy (short path), full pytest, tsc, vitest, build, `git grep -nE "sk-or-v1-[0-9a-f]{20,}"` (empty), `git ls-files --eol | grep w/crlf` (empty).
- [ ] **Step 4: Commit** `docs: Phase 3 decompiler docs and speed numbers`
