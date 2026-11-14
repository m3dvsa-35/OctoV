# Library-Function Recognition (Phase 5a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Known library functions (MSVC runtime, ATL/MFC, common C libraries) get their real
name and a `lib` mark, are skipped by the ranking, and are counted in Triage.

**Architecture:** A short-lived child process (`octov.ext.library_worker`, the only `flirt`
import) matches FLARE FLIRT signatures against the already discovered function starts and
prints raw candidates. A pure policy in `core/analysis/library.py` accepts or drops them. The
API runs the worker as a third engine lane after the slow lane, caches its document and
re-runs naming and ranking.

**Tech Stack:** Python 3.11+, `python-flirt` 0.10, existing `ext.runner` / `ext.queue` /
`ext.cache`; React + TypeScript web UI.

**Spec:** `docs/superpowers/specs/2026-11-14-library-recognition-phase5-design.md`

## Global Constraints

- TDD: failing test first. ruff (line 100) and mypy strict stay clean.
- `flirt` is imported only in `src/octov/ext/library_worker.py`.
- No new fact kind, no risk-score change.
- Policy constants: `MIN_SIZE = 16`, `MIN_PER_SET = 5`.
- Name order: analyst > export > library > suggested > `sub_…`.
- Limits for `config.extensions["library"]`: timeout 120 s, memory 2048 MB, size 64 MB.
- Every UI string in `core/i18n/en.py` and `az.py`; never meaning by colour alone.
- Files are LF (`write_bytes` / `newline="\n"`); stage files explicitly; commits are
  Conventional Commits with the Co-Authored-By trailer from CLAUDE.md.
- Unit tests never use the machine's signature files (`tests/conftest.py` stubs
  `api.library_status` to "not installed").

## Review Focus

1. A sample closed while its library job is queued or waiting for the slow lane: the job must
   end quietly and never touch another sample (test in Task 4).
2. The slow lane fails or finds no functions: `library` ends `unavailable` / `done` with zero
   matches, never stays `queued` (Task 4).
3. A corrupt or foreign cache document / worker output: `failed` with `bad_output`, the sample
   stays usable (Tasks 2 and 4).
4. A function start in a section with no raw data, or at the very end of a section: the worker
   skips it instead of crashing (Task 2).
5. capa and library finishing at the same moment: both results end up in names and ranking
   (Task 4, per-sample apply lock).

---

### Task 1: Policy

**Files:**
- Create: `src/octov/core/analysis/library.py`
- Test: `tests/unit/test_analysis_library.py`

**Interfaces:**
- Produces:
  - `Candidate(rva: int, set: str, names: tuple[str, ...], count: int)` (frozen dataclass;
    `count` = number of distinct names, `names` = at most the first 4)
  - `LibraryMatch(start: int, name: str, source: str)` (frozen dataclass)
  - `accept(candidates: Sequence[Candidate], sizes: Mapping[int, int]) -> dict[int, LibraryMatch]`
  - `MIN_SIZE = 16`, `MIN_PER_SET = 5`

- [ ] **Step 1: failing tests** — `test_unique_names_from_a_present_library_are_accepted`
  (6 candidates of set `a.sig`, one name each, sizes 40 -> 6 matches with `source == "a.sig"`),
  `test_two_names_for_one_function_are_dropped` (`count == 2`, also when the two names come
  from two candidates of different sets for the same rva), `test_tiny_functions_are_dropped`
  (size 15 dropped, 16 kept), `test_a_lone_match_of_a_set_is_dropped` (5 of `a.sig` + 1 of
  `b.sig` -> only the 5), `test_unknown_function_start_is_dropped` (rva not in `sizes`),
  `test_tiny_and_ambiguous_do_not_count_towards_the_set` (4 good + 1 tiny of `a.sig` -> none).
- [ ] **Step 2:** run, see them fail (module missing).
- [ ] **Step 3:** implement `accept`: group candidates by rva; keep an rva when the union of
  names over its candidates has exactly one name, every candidate's `count == 1`, and
  `sizes.get(rva, 0) >= MIN_SIZE`; then drop sets with fewer than `MIN_PER_SET` kept rvas.
- [ ] **Step 4:** tests pass. **Step 5:** commit `feat(analysis): library match policy`.

### Task 2: Worker and adapter

**Files:**
- Create: `src/octov/ext/library_worker.py`, `src/octov/ext/library.py`
- Modify: `pyproject.toml` (core dependency `python-flirt>=0.10,<1`; mypy override
  `module = ["flirt"]`, `ignore_missing_imports` if it ships no stubs), `uv.lock` (`python -m uv lock`)
- Test: `tests/unit/test_ext_library.py`, helper in `tests/samples/builder.py` only if needed

**Interfaces:**
- Produces (`ext/library.py`):
  - `WORKER_VERSION = "1"`
  - `library_sigs_dir(sigs_root: Path) -> tuple[str, Path] | None` — newest `v?X.Y.Z` folder
    holding a `*.sig` or `*.pat`
  - `library_status(sigs_root: Path, finder=importlib.util.find_spec) -> ExtensionStatus` —
    id `library`, `version = WORKER_VERSION`, `rules_version` = folder name, reasons
    `ext.reason.not_installed` / `ext.reason.no_signatures`, `setup_cmd = "octov ext setup library"`
  - `library_command(sample: Path, sigs: Path, starts_file: Path) -> list[str]`
  - `parse_library(doc: dict[str, Any]) -> list[Candidate]` — raises
    `EngineError("bad_output", ...)` unless `engine == "library"`, `version == 1` and the
    candidate rows are well formed
- Produces (`ext/library_worker.py`):
  - `match_file(sample: Path, sigs_dir: Path, starts: Sequence[int]) -> dict[str, Any]` (the
    document of spec §5.2) and `main(argv) -> int` (prints it as JSON; exit 2 on bad arguments)
  - `WINDOW = 0x8000`

- [ ] **Step 1: failing tests.** A fixture builds a synthetic PE with `tests/samples/builder.py`
  containing at least 6 distinct functions of >= 40 bytes, discovers its functions, and writes
  `tmp/sigs/v1.0.0/test.pat` with one line per chosen function: the first 32 bytes as hex,
  `00 0000`, the function length as 4 hex digits, `:0000 <name>` (FLIRT .pat format;
  check the exact line shape against `flirt.parse_pat` before writing the fixture). Tests:
  `test_worker_names_the_functions_it_has_signatures_for` (each chosen start is a candidate
  with its name, `set == "test.pat"`, `count == 1`),
  `test_worker_skips_starts_outside_the_file` (start `0x7fffffff` and a start in a section
  without raw data: no candidate, no exception),
  `test_worker_runs_as_a_child_process` (`run_engine(library_command(...))` + `parse_json` +
  `parse_library` gives the same candidates),
  `test_parse_library_rejects_foreign_documents` (`{"ok": true}`, wrong version, a candidate
  without `rva`), `test_status_needs_signatures` (empty root -> `ext.reason.no_signatures`;
  `finder` returning None -> `ext.reason.not_installed`; with the fixture folder -> ready,
  `rules_version == "v1.0.0"`).
- [ ] **Step 2:** run, fail. **Step 3:** implement. The worker parses the PE with `parse_pe`,
  reads bytes through `ImageView.read(start, WINDOW)`, compiles one matcher per signature file
  (sorted by name), keeps names with offset 0, kind `public`/`local`, not `?`.
- [ ] **Step 4:** pass; `ruff`, mypy. **Step 5:** commit `feat(ext): FLIRT library worker`.

### Task 3: Names, ranking, triage count (core)

**Files:**
- Modify: `src/octov/core/analysis/scoring.py` (`rank_functions`), `analyzers.py` (`Ranking`),
  `report.py` (`build_triage`), `src/octov/ext/apply.py`
- Test: `tests/unit/test_analysis_scoring.py`, `tests/unit/test_ext_apply.py`

**Interfaces:**
- Consumes: `LibraryMatch`, `Candidate`, `accept`, `parse_library`.
- Produces:
  - `rank_functions(..., names, library: Collection[int] = ())` — a library start is left out
    unless a fact of severity `medium` or `high` has evidence in it (directly or through the
    existing data-xref rule).
  - `Ranking` passes `ctx.results.get("library", {})` keys and names with library names merged
    over suggested ones.
  - `build_triage` result gains `"library": {"functions": int, "total": int}`.
  - `apply_library(ctx: AnalysisContext, pipeline: Pipeline, doc: dict[str, Any]) -> None` —
    `ctx.results["library"] = accept(parse_library(doc), {start: fn.size})`, then
    `pipeline.rerun(["naming", "ranking"], ctx)`.

- [ ] **Step 1: failing tests** — `test_library_functions_are_left_out_of_the_ranking`
  (function scoring through suspicious API calls only: ranked without `library`, absent with),
  `test_library_function_with_a_medium_fact_stays_ranked`,
  `test_apply_library_names_and_reranks` (ranked entry of a library function disappears,
  `ctx.results["library"][start].name` set), `test_risk_score_ignores_library_results`
  (score before == after), `test_triage_counts_library_functions`.
- [ ] **Steps 2-5:** fail, implement, pass, commit `feat(analysis): library names in ranking and triage`.

### Task 4: API lane

**Files:**
- Modify: `src/octov/app/api.py`, `src/octov/core/config.py` (`EXTENSION_IDS` gains
  `"library"` with `ExtensionConfig(timeout_s=120, max_size_mb=64, max_memory_mb=2048)`),
  `src/octov/ext/__init__.py` (`ALL_EXTENSIONS` gains `"library"`),
  `src/octov/ext/queue.py` (`QUEUES["library"]`), `tests/conftest.py` (stub
  `api.library_status`), `src/octov/cli/triage.py` + `scripts/baseline_sweep.py` (leave the
  lane off, as for Ghidra)
- Test: `tests/unit/test_library_api.py`, `tests/unit/test_config.py`

**Interfaces:**
- Consumes: Task 2 and 3 names.
- Produces:
  - `job_status(sha)["library"]`; `run_extension(sha, "library", force)`;
    `get_extensions()` includes the library status with `auto_run`.
  - `list_functions` rows: `"library": bool`; `_names()` second element includes library names
    (library over suggested); `suggested` false for library rows.
  - `get_triage(sha)["library"]`.
  - `_Sample.apply_lock: threading.Lock`, taken in `_finish_engine` and the library apply.

Behaviour: at `open_sample` the state is `queued` when the lane will run, else
`unavailable` (`not ready` reason, `ext.reason.pe_only` for raw, `ext.reason.in_memory`,
`ext.reason.too_large`) or `idle` (auto-run off). A thread waits for the slow lane
(`wait_slow(0.5)` loop that stops when the sample was closed); if `functions` ended `failed`
or `unavailable` the lane ends `unavailable` with `needs functions`. Then: cache hit ->
apply; otherwise submit to `QUEUES["library"]` a job that writes the starts to a temp file in
the cache folder, runs `run_engine(library_command(...))`, deletes the temp file in `finally`,
checks `_file_unchanged` before and after, applies under the lock, stores the cache, and ends
`done` / `failed` exactly like `_engine_job`. Tests replace `library_ext.library_command`
with the fake engine (`file` mode, a JSON fixture written by the test from the sample's real
function starts).

- [ ] **Step 1: failing tests** — `test_library_names_reach_the_function_list` (state `done`,
  rows have `library: True` and the names; triage `library.functions == 6`),
  `test_analyst_and_export_names_win_over_library_names`,
  `test_library_result_is_cached` (second open: worker not started, `cached: True`),
  `test_library_unavailable_without_signatures` (default conftest stub),
  `test_library_is_idle_when_auto_run_is_off_and_runs_on_request`,
  `test_raw_samples_are_pe_only`, `test_bad_worker_output_fails_the_job` (fake `garbage`;
  `list_functions` still works), `test_closing_the_sample_drops_the_job` (fake `sleep`; close;
  no exception, queue free for the next sample),
  `test_capa_and_library_results_both_apply` (both fakes; names and capability facts present),
  `test_config_has_library_limits`.
- [ ] **Steps 2-5:** fail, implement, pass (plus the whole `tests/unit -k "ext or triage or app_api"`),
  commit `feat(api): library recognition lane`.

### Task 5: Setup command and strings

**Files:**
- Modify: `src/octov/cli/ext.py` (`octov ext setup library`: only `install_sigs`; status line
  for `library`), `src/octov/core/i18n/en.py`, `az.py`
- Test: `tests/unit/test_ext_cli.py`

Strings (EN; AZ equivalents): `ext.reason.no_signatures` "signature files missing (run: octov
ext setup library)", `ext.library.adds` "Names known library functions (C runtime, MFC, zlib,
OpenSSL…) so you can skip them.", `ext.name.library` if the UI names engines by key,
`functions.library` "lib", `functions.library_hint` "Known library function", 
`functions.hide_library` "Hide library ({n})", `triage.library` "Known library code: {n} of
{m} functions; they are left out of the ranking."

- [ ] Tests: `test_setup_library_installs_only_signatures` (with `--sigs-from` a folder of fake
  `.sig` files and patched pins, following the existing capa setup test), status output has a
  `library` line. Fail, implement, pass, commit `feat(cli): octov ext setup library`.

### Task 6: Web UI

**Files:**
- Modify: `web/src/api/types.ts` (`FunctionSummary.library`, `Triage.library`),
  `web/src/components/Sidebar.tsx`, `TriageView.tsx`, `EngineCard.tsx` (+ wherever engine ids
  are listed), `web/src/state/store.ts` (`hideLibrary`, refresh functions when the `library`
  job turns `done`, as it already does for capa), `web/src/lib/triage.ts`
- Test: `web/src/lib/triage.test.ts` (or the file where list helpers are tested)

**Interfaces:**
- Produces: `visibleFunctions(functions, query, hideLibrary): FunctionSummary[]` in
  `lib/triage.ts` (the current search filter moved out of `Sidebar.tsx`, plus the library
  filter; the current function is the caller's concern).

- [ ] vitest: query filter unchanged; `hideLibrary` drops `library` rows; count helper.
  Implement; `typecheck`, `test`, `build`; `tests/unit/test_web_strings.py` passes; commit
  `feat(ui): library tag, hide toggle, triage line`.

### Task 7: Real signatures, gates, notes

**Files:**
- Create: `tests/unit/test_library_real.py` (skipped unless `~/.octov/capa-sigs` has `.sig`
  files and pip's `t64.exe` exists in the venv)
- Modify: `CLAUDE.md` (status, facts, timings), `README` section if engines are listed there

- [ ] Real test: `t64.exe` -> at least 150 accepted names; `C:\Windows\System32\notepad.exe`
  -> no accepted match whose source is the `atlmfc` file.
- [ ] Gates: ruff format + check, mypy (short path), full pytest (background), npm typecheck /
  test / build, `git grep` key check, `git ls-files --eol | grep w/crlf` empty.
- [ ] Timing on 4 files (first run, cached) and a browser-pane check in EN and AZ with a
  throwaway server on temp settings; record in CLAUDE.md. Commit `docs: ...`.
