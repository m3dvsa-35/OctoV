# Assisted triage Phase 2 (capa + FLOSS extensions) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Optional capa and FLOSS engines feed capabilities and recovered strings into OctoV's facts, score, ranking, Strings tab and UI, without slowing the first view or touching the network.

**Architecture:** Each engine runs as a child process (`sys.executable -m <module> -j`) inside a Windows Job Object, through one global queue per engine. Its JSON is cached under `~/.octov/cache/` and mapped to facts, strings and IOCs. When a result lands, the dependent core analyzers (IOCs, naming, ranking) are re-run.

**Tech Stack:** Python 3.12, ctypes (Job Object), flare-capa 10.x, flare-floss 3.2.x (optional extras), React/TS web UI, pytest/vitest.

**Spec:** `docs/superpowers/specs/2026-11-09-assisted-triage-phase2-design.md` (parent: `docs/superpowers/specs/2026-11-08-assisted-analysis-design.md`). Read both before Task 1, and read CLAUDE.md for the environment quirks (mypy short path, `scripts/npm.py`, LF line endings).

## Global Constraints

- Extras: `capa = ["flare-capa>=10,<11"]`, `floss = ["flare-floss>=3.2,<4"]`; never in the default dependency set.
- Engines run only as `[sys.executable, "-m", <module>, ...]` child processes, below-normal priority, inside a Job Object with a memory limit; never imported into the OctoV process (probe with `importlib.util.find_spec` / `importlib.metadata.version`).
- Config defaults per engine (`extensions.<id>`): `timeout_s: 600`, `max_size_mb: 64`, `max_memory_mb: 4096`.
- Settings: `extensions_auto_run: {"capa": true, "floss": true}` persisted with the UI settings.
- At most one capa and one FLOSS process at a time in the whole app; waiting jobs show `queued`.
- Samples without a real file (carved payloads) → `unavailable` with reason key `ext.reason.in_memory`. They are never written to disk.
- Too large → `unavailable` (`ext.reason.too_large`); timeout / memory / crash / bad JSON → `failed` with a readable reason.
- Cache: `~/.octov/cache/<sha256>/<engine>-<engine_version>-<rules_version>.json.gz`, atomic write (temp + rename), corrupt file = miss.
- capa rules: `~/.octov/capa-rules/<rules_version>/`; installed only by `octov ext setup capa [--from-zip PATH]` (URL + sha256 pinned in code). The app never downloads.
- capa facts: kind `capability`, severity `info` by default, `medium` only for namespace prefixes `host-interaction/process/inject`, `persistence/`, `collection/keylog`, `anti-analysis/anti-vm`, `anti-analysis/obfuscation`, `impact/`, `communication/c2`; never `high`; `lib` rules skipped.
- FLOSS: `origin ∈ {"static","stack","tight","decoded"}`; FLOSS static strings ignored. `obfuscated_strings` (low) when ≥ 5 recovered strings; `hidden_ioc` (medium) **one fact per sample**.
- Engine addresses map onto the containing OctoV function (`FunctionIndex.lookup`); engines never add functions.
- capa explanations per top-level namespace, keys `capa.ns.<namespace>.explain`, EN + AZ.
- No network in tests; tests use recorded JSON fixtures or a fake engine module; integration tests are skipped unless the engine is installed.
- Calibration: 200-file System32 slice (every 22nd file) with both engines. Target: 0 high facts, ≥ 95 % low, high band only `KNOWN_HIGH`. Tune only the medium-prefix list.

## Review Focus

1. **Engine addresses outside the image** (VA below the image base, beyond `SizeOfImage`, or shellcode with base 0): the evidence is dropped or kept as the raw address, never a crash. Tested in Task 5 (`test_capa_addresses_outside_image_are_skipped`).
2. **Engine output from another major version, malformed JSON, or empty stdout with exit 0**: the job ends `failed` with reason "unexpected engine output", and no exception reaches the UI. Tested in Task 2 (`test_bad_json_is_failed`) and Task 5/6 (`test_unknown_schema_rejected`).
3. **Sample closed while its engine job is queued or running**: the job is dropped or killed, no result is written into a closed sample, and no orphan process is left. Tested in Task 7 (`test_close_cancels_queued_and_running`).
4. **Same sample opened twice / re-run clicked while running**: only one job per (sha, engine). Tested in Task 7 (`test_duplicate_submit_is_ignored`).
5. **Corrupt or truncated cache file**: treated as a miss, rerun, overwritten. Tested in Task 3 (`test_corrupt_cache_is_miss`).

---

### Task 1: Extension config, extras and status probe

**Files:**
- Modify: `pyproject.toml` (extras `capa`, `floss`)
- Modify: `src/octov/core/config.py` (`ExtensionConfig`, `Config.extensions`, parsing of `extensions:`)
- Create: `src/octov/ext/__init__.py`
- Modify: `config.yaml.example` (documented `extensions:` block)
- Test: `tests/unit/test_ext_status.py`, `tests/unit/test_config.py`

**Interfaces:**
- Produces: `ExtensionConfig(timeout_s: int = 600, max_size_mb: int = 64, max_memory_mb: int = 4096)`; `Config.extensions: dict[str, ExtensionConfig]` with keys `"capa"`, `"floss"`.
- Produces: `ENGINES = ("floss", "capa")` (lane order); `ExtensionStatus(id, installed: bool, ready: bool, version: str | None, rules_version: str | None, reason_key: str | None, install_cmd: str, setup_cmd: str | None)`; `extension_status(rules_root: Path, finder=importlib.util.find_spec, version_of=importlib.metadata.version) -> list[ExtensionStatus]`; `capa_rules_dir(rules_root: Path) -> tuple[str, Path] | None` (newest `<version>/` containing ≥ 1 `*.yml`).
- `install_cmd` values: `python -m uv sync --extra capa` / `--extra floss`; `setup_cmd` for capa: `octov ext setup capa`.

- [ ] **Step 1: Write failing tests**

```python
def test_missing_engine_is_not_installed(tmp_path):
    st = {s.id: s for s in extension_status(tmp_path, finder=lambda n: None)}
    assert not st["capa"].installed and not st["capa"].ready
    assert st["capa"].reason_key == "ext.reason.not_installed"
    assert st["capa"].install_cmd == "python -m uv sync --extra capa"


def test_capa_without_rules_is_not_ready(tmp_path):
    st = {
        s.id: s
        for s in extension_status(
            tmp_path, finder=lambda n: object(), version_of=lambda n: "10.0.0"
        )
    }
    assert st["capa"].installed and not st["capa"].ready
    assert st["capa"].reason_key == "ext.reason.no_rules"
    assert st["floss"].ready  # FLOSS needs no rules


def test_capa_rules_dir_picks_newest_with_yml(tmp_path):
    (tmp_path / "v9.0.0").mkdir()
    (tmp_path / "v9.0.0" / "a.yml").write_text("x")
    (tmp_path / "v10.0.0").mkdir()
    (tmp_path / "v10.0.0" / "b.yml").write_text("x")
    (tmp_path / "v11.0.0").mkdir()  # empty -> ignored
    assert capa_rules_dir(tmp_path)[0] == "v10.0.0"
```

`test_config.py`: `extensions: {capa: {timeout_s: 30}}` → `cfg.extensions["capa"].timeout_s == 30`, floss keeps 600. An unknown key → `ConfigError`. A non-positive value → `ConfigError`.

- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ext_status.py tests/unit/test_config.py -q` — Expected: FAIL (`ModuleNotFoundError: octov.ext`).
- [ ] **Step 3: Implement** the dataclasses and functions above. Version comparison uses `packaging.version.Version` on the directory names with a leading `v` stripped; ignore names that don't parse.
- [ ] **Step 4: Run** the same command — Expected: PASS. Then `python -m uv lock` and `python -m uv sync --all-extras` (dev venv gets both engines; needed from Task 5 for fixtures). Confirm `.venv/Scripts/python -c "import importlib.util as u; print(u.find_spec('capa'), u.find_spec('floss'))"` prints two specs.
- [ ] **Step 5: Commit** `feat(ext): extension config, extras and status probe`

### Task 2: Engine runner (child process, Job Object, limits)

**Files:**
- Create: `src/octov/ext/runner.py`
- Create: `tests/fixtures/fake_engine.py` (prints canned JSON / sleeps / exits 3 / allocates memory, driven by argv)
- Test: `tests/unit/test_ext_runner.py`

**Interfaces:**
- Produces: `EngineRun(stdout: bytes, stderr_tail: str, elapsed_s: float)`; `EngineError(Exception)` with `.reason: str` (EN text shown as-is) and `.kind: Literal["timeout","memory","crash","cancelled","bad_output"]`.
- Produces: `run_engine(argv: list[str], *, timeout_s: float, max_memory_mb: int, cancel: threading.Event) -> EngineRun`. It raises `EngineError` on: non-zero exit (`crash`, reason includes the last stderr line), timeout (`timeout`, "timed out after N s"), Job Object memory limit hit (`memory`), `cancel` set (`cancelled`).
- Produces: `parse_json(run: EngineRun) -> dict[str, Any]`, which raises `EngineError(kind="bad_output", reason="unexpected engine output")` on empty or non-JSON stdout, or on a non-object root.

- [ ] **Step 1: Write failing tests** (all use `[sys.executable, "tests/fixtures/fake_engine.py", <mode>]`):
  `test_json_output_is_returned` (mode `ok` → `parse_json(run) == {"ok": True}`), `test_nonzero_exit_is_crash` (mode `exit3` → kind `crash`, stderr tail in reason), `test_timeout_kills_process` (mode `sleep` with `timeout_s=1` → kind `timeout` in < 5 s and the child pid is gone), `test_cancel_kills_process` (set `cancel` from a timer after 0.5 s → kind `cancelled`), `test_memory_limit` (mode `alloc` allocating 300 MB with `max_memory_mb=100` → kind `memory`), `test_bad_json_is_failed` (mode `garbage` → `parse_json` raises `bad_output`).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ext_runner.py -q` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement.** `subprocess.Popen` with `creationflags=CREATE_SUSPENDED | BELOW_NORMAL_PRIORITY_CLASS`. Assign it to a Job Object (`CreateJobObjectW`, `SetInformationJobObject` with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY`), then resume the main thread. Read stdout/stderr in threads and poll every 0.1 s for exit, timeout and cancel. Detect a memory kill by querying `JobObjectExtendedLimitInformation.PeakJobMemoryUsed >= limit` after exit. On non-Windows, run without the job (memory limit not enforced; skip that test there).
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ext): isolated engine runner with timeout, cancel and memory limit`

### Task 3: Result cache

**Files:**
- Create: `src/octov/ext/cache.py`
- Test: `tests/unit/test_ext_cache.py`

**Interfaces:**
- Produces: `cache_file(root: Path, sha: str, engine: str, engine_version: str, rules_version: str | None) -> Path` (rules part `none` when `None`; version strings sanitised to `[A-Za-z0-9._-]`); `load(path: Path) -> dict[str, Any] | None`; `store(path: Path, doc: dict[str, Any]) -> None`.

- [ ] **Step 1: Write failing tests:** `test_round_trip` (store then load returns the same dict; file is gzip), `test_version_mismatch_is_miss` (different `engine_version` → another path → `load` is `None`), `test_corrupt_cache_is_miss` (truncated gzip → `None`, no exception), `test_store_is_atomic` (a failing `json.dumps` leaves no partial file and no temp file behind).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ext_cache.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement** with `gzip`, `json`, a temp file in the same directory, and `os.replace`.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ext): per-sample engine result cache`

### Task 4: capa rules setup + `octov ext` CLI

**Files:**
- Create: `src/octov/ext/capa_rules.py`
- Create: `src/octov/cli/ext.py`; Modify: `src/octov/cli/main.py` (register `ext`)
- Test: `tests/unit/test_ext_capa_rules.py`, `tests/unit/test_ext_cli.py`

**Interfaces:**
- Produces: constants `CAPA_RULES_VERSION`, `CAPA_RULES_URL`, `CAPA_RULES_SHA256`. The owner approved downloading the official `mandiant/capa-rules` release matching capa 10 (2026-11-09, blanket approval for this phase); record file name, size and sha256 in the ledger, then pin URL and sha256.
- Produces: `install_rules(rules_root: Path, zip_path: Path | None = None, fetch=_download) -> Path`. It verifies the sha256 (`RulesError("checksum mismatch")` otherwise), rejects members that are absolute or escape the target (`RulesError("unsafe path in archive: <name>")`), extracts to a temp dir, then renames it to `rules_root / CAPA_RULES_VERSION`. An existing target is replaced atomically.
- Produces CLI: `octov ext status` (one line per engine: id, installed, ready, version, rules version, reason or "ready") and `octov ext setup capa [--from-zip PATH]`. Exit code 0 on success; 2 with a message on `RulesError`.

- [ ] **Step 1: Write failing tests** with zips built in `tmp_path` and `fetch` replaced by a function that copies a local zip (no network): `test_from_zip_installs` (`.yml` files present under the version dir), `test_checksum_mismatch_rejected`, `test_zip_slip_rejected` (member `../evil.yml` → `RulesError`, nothing written outside), `test_reinstall_replaces`. CLI: `test_ext_status_lists_engines` (capsys shows `capa` and `floss`), `test_setup_from_zip_cli` (exit 0, path printed).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ext_capa_rules.py tests/unit/test_ext_cli.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement** (`zipfile`, `hashlib.sha256`, `urllib.request` only inside `_download`). The sha256 check covers both the downloaded file and `--from-zip`; for `--from-zip` with a different release, `--allow-unpinned` skips the check and records the version as `local-<sha256[:12]>`.
- [ ] **Step 4: Run** — Expected: PASS. Then run once for real: `.venv/Scripts/python -m octov.cli.main ext setup capa` and `ext status` → capa ready.
- [ ] **Step 5: Commit** `feat(ext): capa rules setup and octov ext CLI`

### Task 5: capa adapter (command, parse, facts)

**Files:**
- Create: `src/octov/ext/capa.py`
- Create: `tests/fixtures/capa/synthetic_injector.json`, `tests/fixtures/capa/notepad_trimmed.json`: recorded with the installed capa on `tests.unit.test_triage_api._suspicious` and on `C:\Windows\System32\notepad.exe`, trimmed to ≤ 30 rules each. A test `test_fixtures_are_capa_10` asserts `meta.version` starts with `10.`.
- Test: `tests/unit/test_ext_capa.py`

**Interfaces:**
- Consumes: `capa_rules_dir` (Task 1), `run_engine`/`parse_json`/`EngineError` (Task 2).
- Produces: `capa_command(path: Path, rules_dir: Path, *, raw: bool, bits: int) -> list[str]` (raw → `-f sc32|sc64`); `CapaMatch(rule: str, namespace: str, attack: tuple[str, ...], mbc: tuple[str, ...], rvas: tuple[int, ...])`; `parse_capa(doc: dict, image_base: int, image_size: int) -> list[CapaMatch]` (raises `EngineError(kind="bad_output")` when `meta.version` major ≠ 10); `MEDIUM_PREFIXES: tuple[str, ...]` (Global Constraints list); `capa_severity(namespace: str) -> Severity`; `capa_facts(matches: list[CapaMatch], index: FunctionIndex | None) -> list[Fact]`.
- Fact shape: `Fact(kind="capability", source_id=rule, severity=capa_severity(ns), title=rule, evidence=(Evidence(f"function {fn:#x}" or "match", rva=r) for each rva, function start first), mitre=attack, tags=mbc + (ns,), explain_key=f"capa.ns.{ns.split('/')[0]}")`.

- [ ] **Step 1: Write failing tests** against the fixtures: `test_lib_rules_skipped`; `test_rvas_are_image_relative` (an address equal to `image_base + 0x1000` → `0x1000`); `test_capa_addresses_outside_image_are_skipped` (VA < base or ≥ base + size → dropped; a match with no address left keeps `rvas == ()` and yields a fact with one location-less evidence item `Evidence("match", value=rule)`); `test_severity_mapping` (`host-interaction/process/inject` → medium, `anti-analysis/anti-debugging/debugger-detection` → info, `persistence/registry/run` → medium, `data-manipulation/encryption/aes` → info); `test_never_high` (every namespace in the notepad fixture → not high); `test_unknown_schema_rejected` (`meta.version="9.3.0"` → `EngineError` bad_output); `test_facts_attach_to_containing_function` (with a `FunctionIndex` built from one function `0x1000-0x1040` and match rva `0x1010`, the first evidence rva is `0x1000`).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ext_capa.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.** Read the capa 10 result document: `rules.<name>.meta.{namespace, attack[].id, mbc[].id, lib}` and `rules.<name>.matches` (address entries `{"type": "absolute", "value": int}`; other address types are skipped). Verify the field paths against the recorded fixture before writing the parser.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ext): capa adapter maps rule matches to capability facts`

### Task 6: FLOSS adapter + string origins

**Files:**
- Create: `src/octov/ext/floss.py`
- Modify: `src/octov/core/analysis/strings.py` (`FoundString.origin`, `FoundString.function`)
- Create: `tests/fixtures/floss/synthetic_stack.json`: recorded with installed FLOSS on a builder sample whose `.text` writes "http://x.example/gate.php" byte by byte onto the stack (add a `stack_string_code(s)` helper to `tests/samples/builder.py`).
- Test: `tests/unit/test_ext_floss.py`, existing `tests/unit/test_analysis_strings.py`

**Interfaces:**
- Produces: `FoundString(..., origin: Literal["static","stack","tight","decoded"] = "static", function: int | None = None)` (new fields last, with defaults, so Phase 1 call sites are unchanged).
- Produces: `floss_command(path: Path, *, raw: bool, bits: int) -> list[str]` (`--only stack tight decoded`, `-j`); `parse_floss(doc: dict, image_base: int, image_size: int) -> list[FoundString]` (offset `-1`, rva = the function or decoding routine RVA, section `None`, `category=classify(value)`); `merge_strings(static: list[FoundString], recovered: list[FoundString]) -> list[FoundString]` (drops recovered values already present statically, keeps order static first); `floss_facts(recovered: list[FoundString], hidden_iocs: list[Ioc]) -> list[Fact]`.
- Facts: `obfuscated_strings` (low, source_id `floss`, evidence = one item per producing function rva, only when `len(recovered) >= 5`); `hidden_ioc` (medium, source_id `floss`, exactly one fact listing every hidden IOC as evidence `Evidence(ioc.value, rva=<producing function>, value=ioc.value)`, only when ≥ 1).

- [ ] **Step 1: Write failing tests:** `test_stack_string_recovered` (fixture yields `origin == "stack"`, value contains `x.example`, `function` is the code function rva); `test_static_duplicates_dropped`; `test_obfuscated_strings_threshold` (4 → no fact, 5 → one low fact); `test_hidden_ioc_is_one_fact` (3 hidden IOCs → exactly one medium fact with 3 evidence items); `test_unknown_schema_rejected` (FLOSS `metadata.version` major ≠ 3 → bad_output). In `test_analysis_strings.py`: `test_found_string_defaults` (`origin == "static"`, `function is None`).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ext_floss.py tests/unit/test_analysis_strings.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.** Read the FLOSS 3 JSON (`strings.stack_strings[]`, `strings.tight_strings[]`, `strings.decoded_strings[]` with `function`/`decoding_routine` addresses); verify the paths against the fixture first. Addresses outside the image are handled as in Task 5.
- [ ] **Step 4: Run** — Expected: PASS; also the full `tests/unit/test_analysis_*.py`.
- [ ] **Step 5: Commit** `feat(ext): FLOSS adapter recovers stack/tight/decoded strings`

### Task 7: Engine queues and the extension lane

**Files:**
- Create: `src/octov/ext/queue.py`
- Modify: `src/octov/core/analysis/pipeline.py` (status fields `elapsed_s`, `cached`; `Pipeline.rerun`)
- Modify: `src/octov/core/analysis/analyzers.py` (`CapaAnalyzer`, `FlossAnalyzer` with `cost="extension"`; IOC/naming/ranking re-run hooks)
- Test: `tests/unit/test_ext_queue.py`, `tests/unit/test_analysis_pipeline.py`

**Interfaces:**
- Produces: `EngineQueue(engine: str)`, one worker thread per engine for the whole process; `submit(sha: str, job: Callable[[threading.Event], None]) -> bool` (False when `(sha)` is already queued or running); `cancel(sha: str) -> None` (removes the queued job; sets the running job's cancel event); `queued(sha) -> bool`; module-level `QUEUES: dict[str, EngineQueue]` for `"capa"` and `"floss"`.
- Produces: `Pipeline.set_state(analyzer_id, state, error=None, *, elapsed_s=None, cached=False)` (public wrapper used by extension jobs); `Pipeline.rerun(ids: Sequence[str], ctx) -> None` (synchronously re-runs the named analyzers in dependency order); status entries gain `elapsed_s: float | None` and `cached: bool`.
- Produces: `extension_analyzers() -> list[Analyzer]` (not part of `default_analyzers()`; the API schedules them). FLOSS completion stores `ctx.results["recovered_strings"]`, sets `ctx.results["strings"] = merge_strings(...)`, then `rerun(["iocs"])` and adds `floss_facts`. capa completion stores `ctx.results["capa"]`, adds `capa_facts`, then `rerun(["naming", "ranking"])` when the slow lane is done (otherwise the slow lane's own naming/ranking picks it up).

- [ ] **Step 1: Write failing tests:** `test_one_job_at_a_time` (two submits for different shas: the second starts only after the first returns); `test_duplicate_submit_is_ignored`; `test_close_cancels_queued_and_running` (cancel on a queued sha → never runs; cancel on the running sha → its event is set); pipeline: `test_rerun_respects_dependencies`, `test_status_has_elapsed_and_cached`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ext_queue.py tests/unit/test_analysis_pipeline.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement** (a `threading.Condition` around a deque per queue; daemon worker; a job exception is caught and logged, never kills the worker).
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(analysis): global engine queues and extension lane`

### Task 8: Capability-aware naming and ranking

**Files:**
- Modify: `src/octov/core/analysis/naming.py`, `src/octov/core/analysis/scoring.py`, `src/octov/core/analysis/analyzers.py` (Naming/Ranking read `ctx.results.get("capa")`)
- Test: `tests/unit/test_analysis_packer_naming.py`, `tests/unit/test_analysis_scoring.py`

**Interfaces:**
- Consumes: `CapaMatch` (Task 5).
- Produces: `suggest_name_from_capa(start: int, rules: Sequence[tuple[str, Severity]]) -> str | None` (exactly one medium rule → slug of the rule name, lowercase, non-alphanumerics → `_`, max 32 chars, + `_<start hex>`; otherwise `None`). Naming prefers it over the API-family name; analyst names still win (unchanged API code).
- Ranking: `rank_functions` adds a reason `capa: <rule>` for every capability fact whose evidence lands in the function. Points follow the existing severity rank, so info adds a reason but no points.

- [ ] **Step 1: Write failing tests:** `test_capa_name_single_medium` (`[("inject thread", "medium"), ("contain loop", "info")]` → `inject_thread_1000`); `test_capa_name_two_medium_is_none`; `test_capa_reason_in_ranking` (info capability fact on a function → its reasons include `capa: contain loop` and its score is unchanged).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_analysis_packer_naming.py tests/unit/test_analysis_scoring.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(analysis): capa-based names and ranking reasons`

### Task 9: WorkbenchApi integration (+ Phase 1 race fixes)

**Files:**
- Modify: `src/octov/app/api.py`
- Test: `tests/unit/test_ext_api.py`, `tests/unit/test_triage_api.py`

**Interfaces:**
- Consumes: Tasks 1–8.
- Produces API methods: `get_extensions() -> list[dict]` (`ExtensionStatus` as dict + `auto_run`); `run_extension(sha: str, ext_id: str, force: bool = False) -> None` (force ignores the cache); `get_strings(..., origin: str | None = None)` (new last parameter); `get_settings/set_settings` include `extensions_auto_run: dict[str, bool]`.
- Behaviour: `open_sample` schedules each ready engine with `auto_run` on, unless the sample has no real file (`unavailable`, `ext.reason.in_memory`) or is larger than `max_size_mb` (`unavailable`, `ext.reason.too_large`). A valid cache file → load, map, `cached=True`, no process. `close_sample` calls `QUEUES[e].cancel(sha)`; a result arriving for a closed sample is discarded. Not-installed or not-ready engines → `unavailable` with the status' `reason_key`.
- Race fixes (from Phase 1 review): `_open_bytes` and `_store(create=True)` check and create under `self._lock`.
- `WorkbenchApi.__init__` gains `cache_dir: Path | None = None` (default `~/.octov/cache`) and `rules_root: Path | None = None` (default `~/.octov/capa-rules`), so tests use `tmp_path`.

- [ ] **Step 1: Write failing tests** (engines replaced by monkeypatching `octov.ext.capa.capa_command` / `floss_command` to run `tests/fixtures/fake_engine.py` printing the recorded fixtures): `test_capa_facts_reach_triage` (after jobs finish: a `capability` fact in findings, medium capabilities in the score contributions); `test_floss_strings_and_hidden_ioc` (`get_strings(origin="stack")` non-empty; triage has one `hidden_ioc`); `test_cache_hit_skips_process` (second API instance on the same cache dir → status `cached: True` and the fake engine is not started); `test_in_memory_sample_unavailable` (an opened payload child → capa `unavailable`, `ext.reason.in_memory`); `test_too_large_unavailable` (`max_size_mb=0` config); `test_auto_run_off_waits_for_run` (status stays `queued`/idle until `run_extension`); `test_force_rerun_replaces_cache`; `test_concurrent_open_same_sample_one_pipeline` and `test_concurrent_first_annotations_one_workspace` (threads, for the race fixes).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ext_api.py tests/unit/test_triage_api.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the full suite `.venv/Scripts/python -m pytest -q -p no:cacheprovider tests --deselect tests/unit/test_baseline_fp.py::test_system32_full_pipeline_baseline` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(app): run capa/FLOSS from the workbench with cache and limits`

### Task 10: Explanations and UI strings (EN/AZ)

**Files:**
- Modify: `src/octov/core/i18n/en.py`, `src/octov/core/i18n/az.py`
- Test: `tests/unit/test_fact_explanations.py`

**Interfaces:**
- Produces keys: `capa.ns.<ns>.explain` for every top-level namespace in the installed capa rules (the test reads them from `CAPA_NAMESPACES` in `octov/ext/capa.py`, a tuple the implementer fills from the rule set); `fact.capability.next`; `fact.obfuscated_strings.explain/.next`; `fact.hidden_ioc.explain/.next`; `ext.reason.not_installed|no_rules|in_memory|too_large`; `ext.capa.adds`, `ext.floss.adds`, `ext.install`, `ext.setup`, `ext.run`, `ext.rerun`, `ext.auto_run`, `ext.cached`, `ext.queued`, `strings.origin`, `strings.origin.static|stack|tight|decoded`, `strings.obfuscated`, `triage.capa_group`.
- Explanations follow the parent spec §5.5: what it is, why attackers do it, what a benign program might do, what to check next.

- [ ] **Step 1: Write failing tests:** extend `test_fact_explanations.py` so every `CAPA_NAMESPACES` entry and the new fact kinds have EN and AZ explanations, and no AZ text equals the EN text.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_fact_explanations.py tests/unit/test_i18n.py -q` — Expected: FAIL.
- [ ] **Step 3: Write the strings** (write files with `read_bytes`/`write_bytes` or the Write tool; LF only).
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(i18n): explain capa namespaces, recovered strings and engine states`

### Task 11: CLI triage waits for engines

**Files:**
- Modify: `src/octov/cli/triage.py`
- Test: `tests/unit/test_triage_cli.py`

**Interfaces:**
- `octov triage FILE [--no-ext]`: without `--no-ext`, the CLI waits for extension jobs too (timeouts come from config). The text/markdown output gets a "Capabilities (capa)" section grouped by namespace and a "Recovered strings" count. JSON gains nothing new beyond the triage dict.

- [ ] **Step 1: Write failing tests** (fake engine via monkeypatch as in Task 9): `test_triage_waits_for_capa` (markdown contains `## Capabilities (capa)`); `test_no_ext_skips_engines` (fake engine not started).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_triage_cli.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(cli): triage includes capa and FLOSS results`

### Task 12: Web UI

**Files:**
- Modify: `web/src/api/{types,client}.ts`, `web/src/state/store.ts`, `web/src/components/{TriageView,StringsView,Sidebar}.tsx`, `web/src/lib/triage.ts`
- Create: `web/src/components/EngineCard.tsx`
- Test: `web/src/lib/triage.test.ts`; `tests/unit/test_web_strings.py` (existing guard)

**Interfaces:**
- Consumes: Task 9 API (`get_extensions`, `run_extension`, `get_strings` origin, settings `extensions_auto_run`), Task 10 keys.
- Produces helpers: `groupByNamespace(rows: CapabilityRow[]): { namespace: string; rows: CapabilityRow[] }[]` (top-level namespace from the `tags` entry containing `/`, sorted by count desc, `other` last); `jobLabel(job: {state; elapsed_s; cached}): string` (e.g. `running · 42 s`, `done · cached`).
- Behaviour: `pollJobs` refreshes triage/findings/functions **each time any job changes to done/failed** (not only when all are finished). Engine chips have a menu with Run / Re-run. `EngineCard` (not installed / not ready) shows `ext.<id>.adds`, the copyable install/setup commands, and the `auto_run` switch, with no download button. The Capabilities card groups capability facts by namespace (collapsible, count in the header). The function list shows a `capa N` text badge. The Strings tab gets an origin column and an "Obfuscated" chip (`origin != "static"`).

- [ ] **Step 1: Write failing vitest** for `groupByNamespace` (two namespaces + one without namespace → order by count, `other` last) and `jobLabel` (running/done-cached/queued/failed).
- [ ] **Step 2: Run** `.venv/Scripts/python scripts/npm.py test` — Expected: FAIL.
- [ ] **Step 3: Implement** the helpers and components.
- [ ] **Step 4: Run** `scripts/npm.py test`, `scripts/npm.py run typecheck`, `scripts/npm.py run build`, `pytest tests/unit/test_web_strings.py` — Expected: all PASS. Manual check in the desktop window (CLAUDE.md screenshot recipe) on the synthetic injector and notepad.exe, EN/Night and AZ/Normal, with engines installed and with capa rules dir renamed away (EngineCard visible).
- [ ] **Step 5: Commit** `feat(ui): capa capabilities, recovered strings and engine cards`

### Task 13: Calibration sweep, baseline test, docs

**Files:**
- Modify: `scripts/baseline_sweep.py` (`--ext` runs both engines with the real queue; `--stride N`, default 1; adds `capa_n`, `floss_n`, `ext_s`, `ext_state` per row)
- Modify: `tests/unit/test_baseline_fp.py` (engine-aware slice test, skipped unless both engines are ready)
- Modify: `README.md` (Extensions section: install, setup, what each adds), `CLAUDE.md` (status, layout `src/octov/ext/`, baseline numbers)
- Test: `tests/unit/test_baseline_fp.py`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the failing test** `test_system32_slice_with_engines` (skipif not ready): run the full pipeline + engines on every 400th System32 file (≈ 11 files, CI-sized). Assert 0 high facts, no high band outside `KNOWN_HIGH`, and every engine state in `done|unavailable`.
- [ ] **Step 2: Run** it — Expected: PASS or FAIL. If it fails on a capa namespace, that is the calibration signal for Step 3.
- [ ] **Step 3: Calibrate:** `.venv/Scripts/python scripts/baseline_sweep.py --ext --stride 22 %TEMP%/sweep_ext.jsonl` (200 files). If high band outside `KNOWN_HIGH` or < 95 % low: shorten `MEDIUM_PREFIXES` (never touch band thresholds or weights), add a `test_capa_severity` case for each change, rerun the sweep. Record the final numbers (bands, high facts, engine median/p99/max seconds, failures) in CLAUDE.md.
- [ ] **Step 4: Full verification:** ruff format + check, mypy (short path), full pytest, tsc, vitest, build, `git grep -nE "sk-or-v1-[0-9a-f]{20,}"` (empty), `git ls-files --eol | grep w/crlf` (empty).
- [ ] **Step 5: Commit** `test(analysis): engine calibration slice; docs for extensions`
