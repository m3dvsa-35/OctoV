# M5 AI Analyst Overlay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One confirmed request sends a bounded, previewed evidence bundle to an OpenAI-compatible model; the cited, validated answer is shown in an AI tab and as an overlay on the Relations graph.

**Architecture:** `core/ai/` = `bundle` (evidence -> exact text + hash), `client` (stdlib HTTPS chat completions, primary + fallback endpoint), `report` (prompt, tolerant JSON parse, citation validation). `WorkbenchApi` adds status / preview / analyse (background job, cache) / report. React: AI tab + Relations overlay.

**Tech Stack:** Python 3.12 standard library (`urllib.request`, `http.server` for the fake in tests), React/TS, pytest/vitest.

**Spec:** `docs/superpowers/specs/2026-11-11-ai-overlay-m5-design.md` (parent: `2026-11-08-assisted-analysis-design.md`). Read CLAUDE.md first (secrets rules, mypy short path, `scripts/npm.py`, LF only, heredoc pitfalls).

## Global Constraints

- **Owner's decision (B):** nothing is sent without the analyst confirming the preview of exactly that bundle, every time. `ai_analyse` takes the previewed hash; a different current hash sends nothing.
- The key comes only from `config.ai.api_key` (filled from `OCTOV_AI_KEY`); it never appears in errors, logs, previews, cache files, reports, test fixtures or the repo.
- Never the binary or raw bytes: only what `build_bundle` produces; the request's user message is `Bundle.text` byte for byte.
- `https://` to any host, `http://` only to loopback; anything else is refused before a connection is made.
- No new runtime dependency. Tests never use the network: a local `http.server` fake on 127.0.0.1.
- No new facts, no score change: the AI report is a separate, labelled opinion. The triage CLI and baseline sweeps never call the AI.
- Evidence text is untrusted data: the system prompt says so, and output is only parsed.
- Never colour alone; every UI string in `en.py` and `az.py`; API parameter order = Python signature order.
- Stage files explicitly (`git add <paths>`); never `git add -A` / `git add src` (stray untracked copies exist in `src/octov/ext/ghidra/`).

## Review Focus

1. **Confirmation cannot be bypassed or go stale**: no code path reaches the network without a hash equal to the current bundle's; a rename between preview and send is refused; the body sent equals the previewed text. Tests in Task 4.
2. **Key leakage**: 401/429/timeouts/garbage/exceptions, job errors, cache files and `ai_status` never contain the key or an `Authorization` header. Tests in Tasks 2 and 4.
3. **Hostile evidence**: strings/names containing instructions or JSON fragments cannot change what is validated; invented fact ids / addresses / IOCs are dropped. Tests in Task 3.
4. **Model misbehaviour**: empty reply, prose instead of JSON, huge reply, wrong types -> a clear failed state, never an exception in the UI thread or a spinner forever. Tests in Tasks 3-4.
5. **Plain-HTTP remote endpoint or redirect**: refused; a redirect is not followed to another host. Test in Task 2.

---

### Task 1: Evidence bundle

**Files:**
- Create: `src/octov/core/ai/bundle.py`
- Modify: `src/octov/core/config.py` (`AIConfig.max_chars: int = 24000`), `config.yaml.example`
- Test: `tests/unit/test_ai_bundle.py`

**Interfaces:**
- Produces: `BundleInput` (plain dataclass the API fills: `name, sha256, size, format, bits, is_dll, entry_point, compile_time, signature, packer, score, band, facts: Sequence[Fact], functions: Sequence[FunctionEvidence], iocs: Sequence[tuple[str, str]], imports: Mapping[str, Sequence[str]], sections: Sequence[tuple[str, str, float]], notes: Sequence[tuple[int, str, str]]`).
- Produces: `FunctionEvidence(start, name, score, reasons, apis: Sequence[tuple[str, str | None]], callers: Sequence[tuple[int, str]], callees: Sequence[tuple[int, str]], strings: Sequence[str], code: str | None, code_kind: Literal["pseudo_c","asm"] | None)`.
- Produces: `Bundle(doc: dict, text: str, hash: str, omitted: dict[str, int], fact_ids: frozenset[str], functions: frozenset[int], iocs: frozenset[str])`; `build_bundle(data: BundleInput, budget_chars: int = 24000) -> Bundle`. `text` = `json.dumps(doc, ensure_ascii=False, indent=1)`; addresses in `doc` are hex strings (`"0x1000"`).
- Caps: findings 60, functions 13, callers/callees 8 each, strings per function 8 (each cut at 120 chars), IOCs 40, code per function 2500 chars, notes 40.

- [ ] **Step 1: Write failing tests:** `test_bundle_has_sample_findings_functions`, `test_addresses_are_hex_and_ids_are_citable` (`fact_ids`, `functions`, `iocs` sets), `test_code_is_added_in_rank_order_until_the_budget` (omitted counts), `test_long_code_and_strings_are_cut`, `test_hash_is_stable_and_changes_with_content`, `test_text_round_trips_as_json`, `test_no_raw_bytes_or_paths` (only the file name, not its folder).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ai_bundle.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** plus `tests/unit/test_config.py` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai): bounded evidence bundle`

### Task 2: OpenAI-compatible client

**Files:**
- Create: `src/octov/core/ai/client.py`, `tests/fixtures/fake_llm.py` (in-process `ThreadingHTTPServer` helper)
- Test: `tests/unit/test_ai_client.py`

**Interfaces:**
- Produces: `Endpoint(base_url, model, key: str | None)` with `host`, `local` (loopback); `endpoints(cfg: AIConfig) -> list[Endpoint]` (primary only if it has a key or is local; then fallback); `AIError(kind, reason)`, kind in `no_endpoint|insecure_endpoint|auth|rate_limit|timeout|network|bad_response`; `chat(endpoint, system, user, timeout_s) -> str`; `ask(endpoints, system, user, timeout_s) -> tuple[str, Endpoint]` (first success; raises the last error; `no_endpoint` when the list is empty).

- [ ] **Step 1: Write failing tests** against the fake: `test_chat_returns_the_message_content` (also asserts method, path `/chat/completions`, bearer header, model and both messages in the body), `test_local_endpoint_sends_no_authorization_without_a_key`, `test_401_is_auth_and_hides_the_key`, `test_429_is_rate_limit`, `test_timeout`, `test_garbage_and_missing_fields_are_bad_response`, `test_plain_http_to_a_remote_host_is_refused_without_connecting`, `test_redirect_is_not_followed`, `test_ask_falls_back_and_reports_which_endpoint_answered`, `test_endpoints_order_and_key_rules`, `test_error_text_never_contains_key_or_body`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ai_client.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai): OpenAI-compatible client with fallback endpoint`

### Task 3: Prompt, report parsing, citation validation

**Files:**
- Create: `src/octov/core/ai/report.py`
- Test: `tests/unit/test_ai_report.py`

**Interfaces:**
- Consumes: `Bundle`, `i18n.ai_language_instruction`.
- Produces: `system_prompt(lang) -> str`; `AIReport(summary, assessment, confidence, story, points, links, dropped: int)` with `to_dict()`; `parse_report(text, bundle) -> AIReport` (raises `AIError("bad_response", …)`); `cited_functions(report) -> dict[int, list[str]]` (address -> notes, for the overlay).
- Limits: summary 1200 chars, story 12 steps, points 12, links 20, each text 600 chars; reply longer than 200 000 chars -> `bad_response`.

- [ ] **Step 1: Write failing tests:** `test_parses_plain_and_fenced_json`, `test_invalid_citations_are_removed_and_counted`, `test_point_without_valid_evidence_is_dropped`, `test_link_needs_two_known_functions`, `test_addresses_accept_hex_and_decimal`, `test_wrong_types_and_unknown_enums_fall_back_safely` (assessment -> `suspicious`? no: unknown -> `bad_response`; missing lists -> empty), `test_prose_empty_or_huge_reply_is_bad_response`, `test_injection_text_in_evidence_does_not_become_a_citation`, `test_system_prompt_has_schema_data_warning_and_language`, `test_texts_are_capped`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ai_report.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai): cited report with evidence validation`

### Task 4: WorkbenchApi integration

**Files:**
- Modify: `src/octov/app/api.py`
- Test: `tests/unit/test_ai_api.py`

**Interfaces:**
- Consumes: Tasks 1-3, Phase 4 call graph, Phase 3 pseudo-C cache (`_decomp_cached`, never starts Ghidra).
- Produces: `ai_status()`, `ai_preview(sha)`, `ai_analyse(sha, confirmed_hash, force=False)`, `get_ai_report(sha)` as in spec §5.4; `job_status["ai"]`; cache `ai-<model>-<hash>.json.gz` via `octov.ext.cache`.

- [ ] **Step 1: Write failing tests** with the fake server as the configured local endpoint: `test_status_lists_endpoints_without_the_key`, `test_preview_is_what_gets_sent` (request body's user message == preview text), `test_nothing_is_sent_without_the_current_hash` (wrong hash, and a rename between preview and send -> `ai.preview_changed`, zero requests), `test_report_is_validated_and_cached` (second analyse with the same evidence makes no request; `force` does), `test_failure_ends_failed_with_a_key_free_reason` (401 with a key configured), `test_bad_reply_is_failed_not_stuck`, `test_no_endpoint`, `test_not_ready_before_discovery`, `test_raw_sample_works`, `test_report_gone_after_evidence_changes` (`get_ai_report` is `None` for a new hash).
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ai_api.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the new file plus `tests/unit/test_app_api.py tests/unit/test_relations_api.py tests/unit/test_no_secrets.py` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(app): AI analyst in the workbench API`

### Task 5: Web UI — AI tab and Relations overlay

**Files:**
- Create: `web/src/components/AiView.tsx`, `web/src/lib/ai.ts`, `web/src/lib/ai.test.ts`
- Modify: `web/src/api/{types,client}.ts`, `web/src/state/store.ts`, `web/src/App.tsx`, `web/src/components/RelationsView.tsx`, `web/src/components/TriageView.tsx`, `src/octov/core/i18n/{en,az}.py`

**Interfaces:**
- Consumes: Task 4 API.
- Produces helpers: `aiNotes(report) -> Map<number, string[]>` (function -> notes from points/story/links); `overlayEdges(report, shown: Set<number>, existing: Set<string>) -> {id, src, dst, why}[]` (AI links between shown nodes; `existing` edges are marked, not duplicated); `chips(point) -> {kind, label, target}[]`; `aiError(message, t)`.

- [ ] **Step 1: Write failing vitest:** `aiNotes`, `overlayEdges` (hidden ends dropped, duplicates of call edges flagged), `chips`, `aiError`.
- [ ] **Step 2: Run** `.venv/Scripts/python scripts/npm.py test` — Expected: FAIL.
- [ ] **Step 3: Implement** helpers, the AI tab (states: no endpoint, not ready, preview + confirm, running, failed with "look again", report), store slice (`aiReport`, refreshed with jobs), Relations overlay with a switch, Triage line, strings.
- [ ] **Step 4: Run** `scripts/npm.py test`, `run typecheck`, `run build`, `pytest tests/unit/test_web_strings.py tests/unit/test_i18n.py` — Expected: PASS. Browser check with the fake server as a local endpoint (EN and AZ): preview, confirm, report, chips navigate, overlay on Relations, failure state.
- [ ] **Step 5: Commit** `feat(ui): AI analyst tab and relations overlay`

### Task 6: Real request, docs, final verification

**Files:**
- Modify: `README.md`, `CLAUDE.md`
- Test: full gates

- [ ] **Step 1: One real request** with the synthetic injector sample against the configured endpoint (the owner's `OCTOV_AI_KEY`; only synthetic evidence is sent). Record model, latency, whether the reply parsed, how many citations were dropped. If the default model is unavailable, note it as a ruling and what was used instead; never print the key.
- [ ] **Step 2: Docs** — README (AI analyst section, privacy wording, status table), CLAUDE.md (status, layout, facts, numbers).
- [ ] **Step 3: Full verification:** ruff format + check, mypy (short path), full pytest, tsc, vitest, build, `git grep -nE "sk-or-v1-[0-9a-f]{20,}"` (empty), `git ls-files --eol | grep w/crlf` (empty).
- [ ] **Step 4: Commit** `docs: M5 AI analyst docs and first real run`
