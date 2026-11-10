# Phase 4 Relations / Search / Symbols / Memory Map Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show how the parts of a sample are linked: a Relations tab (callers/callees neighbourhood with scores, API families and the path from the entry point), a Search tab (bytes with wildcards, instruction text, immediates), Symbols in the sidebar and a memory map in Overview.

**Architecture:** Pure-Python helpers over existing slow-lane results (`Function.calls`, `XrefIndex`, `ranking`), exposed through four new `WorkbenchApi` methods; React views reuse xyflow + the ELK worker and the virtualised-list pattern. No new facts, no new analyzer.

**Tech Stack:** Python 3.12, React/TS, xyflow, elkjs (worker), @tanstack/react-virtual, pytest/vitest.

**Spec:** `docs/superpowers/specs/2026-11-10-relations-phase4-design.md` (parent: `2026-11-08-assisted-analysis-design.md`). Read CLAUDE.md first (mypy short path, `scripts/npm.py`, LF only, heredoc pitfalls).

## Global Constraints

- No new facts, scores or analyzer status chips; the System32 baselines must not change.
- The call graph is built lazily on first use and cached on the sample (`_Sample`), guarded by the API lock.
- Depths are clamped to 1..3; `max_nodes` = 60; search `limit` default 500, clamped to 1..2000.
- Never colour alone (score as number + word, path edges labelled, permissions as text); every new UI string in `en.py` and `az.py`.
- API parameter order = Python signature order (pywebview bridge passes positionally).
- Stage files explicitly (`git add <paths>`): two untracked copies `src/octov/ext/ghidra/* (1).py` are not part of this work and must not be committed or deleted.

## Review Focus

1. **Cycles and recursion in the call graph** (mutual recursion, self-calls, a function that is both caller and callee of the centre): BFS terminates, roles are right (`both`), no duplicate nodes/edges. Tests in Task 1.
2. **Truncation**: a hub with thousands of callers (e.g. a memcpy-like function) returns ≤ 60 nodes fast, says `truncated`, and the hidden counts add up. Test in Task 1 (`test_hub_is_truncated_with_hidden_counts`).
3. **Search input**: malformed patterns/numbers give a clear error, not an exception or a full-file match; an all-wildcard pattern is refused. Tests in Task 2.
4. **Slow lane not finished yet**: relations/search/symbols asked before functions and xrefs exist return an empty/"not ready" result, never crash. Test in Task 3 (`test_relations_before_discovery_finishes`).
5. **Raw samples**: no imports/exports/sections; every new API still answers. Test in Task 3.

---

### Task 1: Call graph core

**Files:**
- Create: `src/octov/core/analysis/callgraph.py`
- Test: `tests/unit/test_analysis_callgraph.py`

**Interfaces:**
- Consumes: `cfg.Function` (`start`, `calls`), `xrefs.XrefIndex` (`from_function`, `imports_called`), `naming.API_FAMILIES`, `scoring.SUSPICIOUS_FAMILIES`, `pe_parser.normalize_api`.
- Produces: `CallGraph.build(functions: Mapping[int, Function], xrefs: XrefIndex | None) -> CallGraph` with `callees(start) -> tuple[int, ...]`, `callers(start) -> tuple[int, ...]`, `recursive(start) -> bool`.
- Produces: `Neighbour(start, role: Literal["center","caller","callee","both"], distance: int, hidden_callers: int, hidden_callees: int)`; `Neighbourhood(center, nodes: tuple[Neighbour, ...], edges: tuple[tuple[int, int], ...], truncated: bool)`; `CallGraph.neighbourhood(center, callers_depth=2, callees_depth=2, max_nodes=60) -> Neighbourhood`.
- Produces: `CallGraph.path_to(center, roots: Iterable[int]) -> tuple[int, ...]` (root first, centre last; `()` when unreachable or the centre is a root).
- Produces: `ApiUse(name, family: str | None, suspicious: bool)`; `apis_of(xrefs: XrefIndex | None, start) -> tuple[ApiUse, ...]` (normalised name without `dll!` and A/W suffix, unique, suspicious first then by name).

- [ ] **Step 1: Write failing tests** (functions built by a small helper `fn(start, calls)`): `test_callers_and_callees`, `test_tail_jump_counts_as_call` (jump xref to another function's start), `test_neighbourhood_depth_limits`, `test_mutual_recursion_terminates_and_marks_both`, `test_self_call_is_recursive_not_an_edge`, `test_hub_is_truncated_with_hidden_counts` (centre with 500 callers, `max_nodes=60`), `test_path_from_entry` (shortest of two chains), `test_path_empty_when_unreachable_or_root`, `test_apis_of_normalises_and_orders`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_analysis_callgraph.py -q` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(analysis): call graph neighbourhoods and entry paths`

### Task 2: Search core

**Files:**
- Create: `src/octov/core/analysis/search.py`
- Test: `tests/unit/test_analysis_search.py`

**Interfaces:**
- Produces: `parse_pattern(text) -> tuple[int | None, ...]`; `parse_number(text) -> int` (`0x..`, `..h`, decimal; `ValueError` otherwise); `search_bytes(data, pattern, limit) -> tuple[list[int], bool]` (offsets, truncated); `InsnHit(address, function, text)`; `search_text(functions, query, limit) -> tuple[list[InsnHit], bool]`; `search_immediate(functions, value, limit) -> tuple[list[InsnHit], bool]`.

- [ ] **Step 1: Write failing tests:** `test_parse_pattern_bytes_and_wildcards` (`"4d5a ?? 00"`, `"4D 5A ? 00"`), `test_parse_pattern_rejects_bad_input` (odd digits, non-hex, empty, all wildcards), `test_search_bytes_wildcard_and_overlapping_hits`, `test_search_bytes_limit_truncates`, `test_search_bytes_treats_regex_specials_literally` (pattern bytes `2E 2A 5B`), `test_search_text_case_insensitive_and_comment`, `test_search_immediate_matches_operand_target_and_data_ref`, `test_search_immediate_does_not_match_substring` (`0x10` must not hit `0x100`), `test_parse_number`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_analysis_search.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(analysis): byte, instruction-text and immediate search`

### Task 3: WorkbenchApi — relations, search, symbols, memory map

**Files:**
- Modify: `src/octov/app/api.py`
- Test: `tests/unit/test_relations_api.py`

**Interfaces:**
- Consumes: Tasks 1-2.
- Produces: `get_relations(sha, start, callers=2, callees=2)`, `search(sha, kind, query, limit=500)`, `get_symbols(sha)`, `get_memory_map(sha)` exactly as in spec §5.3. Names in results use the same resolution as `list_functions` (analyst name, export, suggested, `sub_…`).

- [ ] **Step 1: Write failing tests** on the synthetic injector (`_suspicious`) and a two-function synthetic PE where needed: `test_relations_center_apis_and_score`, `test_relations_depth_is_clamped`, `test_relations_unknown_start`, `test_relations_before_discovery_finishes` (pipeline slow lane not started -> `ApiError("relations.not_ready")`), `test_search_bytes_maps_offsets_to_rvas` (MZ header hit: `rva` 0 or null per mapping, `.text` hit has rva + function), `test_search_text_and_value`, `test_search_bad_input_is_api_error`, `test_symbols_group_imports_by_dll_with_refs`, `test_memory_map_regions_in_file_order` (headers, sections, overlay; sizes add up to the file size), `test_raw_sample_answers_everything`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_relations_api.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the new file plus `tests/unit/test_app_api.py tests/unit/test_triage_api.py` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(app): relations, search, symbols and memory map in the workbench API`

### Task 4: Web UI — Relations tab

**Files:**
- Create: `web/src/lib/relations.ts`, `web/src/lib/relations.test.ts`, `web/src/components/RelationsView.tsx`
- Modify: `web/src/api/{types,client}.ts`, `web/src/state/store.ts` (MainView), `web/src/App.tsx`, `web/src/components/TriageView.tsx`, `src/octov/core/i18n/{en,az}.py`

**Interfaces:**
- Consumes: `get_relations`.
- Produces helpers: `nodeSize(node) -> {width, height}`; `toRelationsGraph(rel) -> ElkGraph-like {children, edges}` (direction RIGHT; edge `onPath` when consecutive in `rel.path`); `chipList(apis, max=4) -> {shown, more}` (suspicious first); `scoreWord(score) -> "high"|"medium"|"low"|null` (≥ 30 high, ≥ 12 medium, > 0 low).

- [ ] **Step 1: Write failing vitest:** `toRelationsGraph` (node count, edge ids unique, `onPath` only for path edges), `chipList`, `scoreWord`, `nodeSize` grows with chips/hints.
- [ ] **Step 2: Run** `.venv/Scripts/python scripts/npm.py test` — Expected: FAIL.
- [ ] **Step 3: Implement** the helpers, the view (states: no function, not ready, loading, graph), tab wiring, Triage jump, strings.
- [ ] **Step 4: Run** `scripts/npm.py test`, `run typecheck`, `run build`, `pytest tests/unit/test_web_strings.py tests/unit/test_i18n.py` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ui): relations tab with callers, callees and entry path`

### Task 5: Web UI — Search tab, Symbols, memory map

**Files:**
- Create: `web/src/components/SearchView.tsx`, `web/src/components/MemoryMap.tsx`, `web/src/lib/search.ts`, `web/src/lib/search.test.ts`
- Modify: `web/src/components/Sidebar.tsx`, `web/src/components/OverviewView.tsx`, `web/src/api/{types,client}.ts`, `web/src/state/store.ts`, `web/src/App.tsx`, `src/octov/core/i18n/{en,az}.py`

**Interfaces:**
- Consumes: `search`, `get_symbols`, `get_memory_map`.
- Produces helpers: `symbolRows(symbols, query) -> Row[]` (DLL header rows + import rows + export rows, filtered case-insensitively, empty groups dropped); `mapSegments(regions, minPercent=3) -> {name, percent}[]` (percentages sum to 100, each ≥ minPercent).

- [ ] **Step 1: Write failing vitest:** `symbolRows` (grouping, filter, empty groups dropped), `mapSegments` (sum 100, minimum width, single region).
- [ ] **Step 2: Run** `scripts/npm.py test` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `scripts/npm.py test`, `run typecheck`, `run build`, `pytest tests/unit/test_web_strings.py tests/unit/test_i18n.py` — Expected: PASS. Browser check (`octov serve`, EN and AZ): relations graph on the synthetic injector and a System32 DLL, re-centre, depth switch, search of each kind, symbols -> xref popover, memory map click.
- [ ] **Step 5: Commit** `feat(ui): search tab, symbols list and memory map`

### Task 6: Speed check, docs, final verification

**Files:**
- Modify: `README.md`, `CLAUDE.md`
- Test: full gates

- [ ] **Step 1: Measure** on a large System32 DLL (≥ 15 000 functions): call-graph build, `get_relations` (warm), byte search, text search, value search; compare with spec §5.5; tune or note a ruling.
- [ ] **Step 2: Docs** — README (Workbench UI section + status table), CLAUDE.md (status, layout, numbers).
- [ ] **Step 3: Full verification:** ruff format + check, mypy (short path), full pytest, tsc, vitest, build, `git grep -nE "sk-or-v1-[0-9a-f]{20,}"` (empty), `git ls-files --eol | grep w/crlf` (empty).
- [ ] **Step 4: Commit** `docs: Phase 4 relations docs and speed numbers`
