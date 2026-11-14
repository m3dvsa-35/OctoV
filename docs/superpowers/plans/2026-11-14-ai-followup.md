# M5b AI Follow-up Questions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The analyst asks follow-up questions about a sample in the AI tab; each question's whole message is previewed and confirmed, and the answer comes back with validated citations.

**Architecture:** `core/ai/chat.py` composes one user message (evidence + focus function + history + question) whose text is both the preview and the request; `WorkbenchApi` adds preview / ask (background job, hash confirmation) / get / clear; the AI tab gains a conversation and a question box.

**Tech Stack:** Python 3.12 standard library, React/TS, pytest/vitest.

**Spec:** `docs/superpowers/specs/2026-11-14-ai-followup-design.md` (parent: `2026-11-11-ai-overlay-m5-design.md`). Read CLAUDE.md first.

## Global Constraints

- Owner's decision (B): nothing is sent without confirming the preview of exactly that message, every time; one chosen destination, no automatic fallback (M5 rules unchanged).
- The request's user message equals the previewed text byte for byte; the key never appears anywhere but the Authorization header to its own host.
- Limits: question 1..1000 chars; last 6 turns; each included answer cut to 1500 chars; stored answer cut to 4000 chars; at most 50 turns kept (oldest dropped).
- Evidence and earlier answers are data; only the system prompt carries rules. Defensive only.
- Never colour alone; strings in `en.py` and `az.py`; API parameter order = Python signature order.
- Stage files explicitly (never `git add -A` / `git add src`); read gate output before committing (pipes hide exit codes).

## Review Focus

1. **Sent equals shown, for the whole message**: history and the focus function are inside the hashed text; a new turn, a rename or a different focus between preview and send is refused. Tests in Task 2.
2. **Stored conversation as an injection path**: an earlier answer (model text) re-sent as history cannot change validation or add citations; it is cut and clearly delimited. Tests in Tasks 1-2.
3. **Concurrency**: a question while the report request or another question runs is refused or queued, never two requests; closing the sample mid-request stores nothing. Test in Task 2.
4. **Unbounded growth**: long conversations and long answers stay within the limits on disk and in the message. Tests in Task 1.

---

### Task 1: Compose and parse (`core/ai/chat.py`)

**Files:** Create `src/octov/core/ai/chat.py`; Test `tests/unit/test_ai_chat.py`.

**Interfaces:**
- Consumes: `Bundle`, `FunctionEvidence`, `bundle._function` (row builder), `report._extract`, `report._Checker`/`_address`, `i18n.ai_language_instruction`.
- Produces: `Turn` (dataclass with `to_dict`/`from_dict`), `ChatMessage(text, hash, functions: frozenset[int])`, `compose(bundle, question, history: Sequence[Turn], focus: FunctionEvidence | None) -> ChatMessage`, `validate_question(text) -> str`, `chat_system_prompt(lang) -> str`, `Answer(text, functions, findings, iocs, dropped)`, `parse_answer(text, bundle, extra_functions: frozenset[int]) -> Answer`, constants `MAX_QUESTION`, `HISTORY_TURNS`, `MAX_TURNS`.

- [ ] **Step 1: Write failing tests:** `test_compose_sections_in_order`, `test_focus_added_only_when_not_in_bundle`, `test_history_is_capped_and_answers_cut`, `test_hash_changes_with_question_history_and_focus`, `test_question_validation`, `test_parse_json_answer_with_citations`, `test_prose_answer_is_kept_without_citations`, `test_bad_citations_dropped_and_focus_function_is_citable`, `test_empty_or_huge_reply_is_bad_response`, `test_history_text_cannot_add_citations`, `test_turn_round_trip`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ai_chat.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai): follow-up question message and answer parsing`

### Task 2: WorkbenchApi

**Files:** Modify `src/octov/app/api.py`; Test `tests/unit/test_ai_chat_api.py`.

**Interfaces:** `ai_chat_preview(sha, question, focus=None)`, `ai_ask(sha, question, confirmed_hash, focus=None, endpoint=0)`, `get_ai_chat(sha)`, `clear_ai_chat(sha)`; `job_status["ai_chat"]`; store `ai-chat-none.json.gz` via `octov.ext.cache`.

- [ ] **Step 1: Write failing tests** (fake server): `test_question_preview_is_what_gets_sent`, `test_nothing_sent_without_current_hash` (wrong hash; rename after preview; different focus), `test_turn_is_stored_and_returned_with_valid_citations`, `test_history_goes_into_the_next_question`, `test_focus_function_outside_the_bundle`, `test_bad_question`, `test_failure_is_failed_and_stores_nothing`, `test_one_request_at_a_time`, `test_clear`, `test_no_endpoint_and_not_ready`.
- [ ] **Step 2: Run** `.venv/Scripts/python -m pytest tests/unit/test_ai_chat_api.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** plus `tests/unit/test_ai_api.py tests/unit/test_no_secrets.py` — Expected: PASS.
- [ ] **Step 5: Commit** `feat(app): follow-up questions in the workbench API`

### Task 3: Web UI

**Files:** Modify `web/src/components/AiView.tsx`, `web/src/api/{types,client}.ts`, `web/src/state/store.ts`, `web/src/lib/ai.ts`, `web/src/lib/ai.test.ts`, `web/src/components/RelationsView.tsx`, `src/octov/core/i18n/{en,az}.py`.

**Interfaces:** helpers `firstSentence(text, max=140)`, `aiNotes(report, turns)` (turn citations add notes).

- [ ] **Step 1: Write failing vitest:** `firstSentence`, `aiNotes` with turns.
- [ ] **Step 2: Run** `.venv/Scripts/python scripts/npm.py test` — Expected: FAIL.
- [ ] **Step 3: Implement** helpers, conversation + question box + preview/confirm + clear, store slice `aiChat`, overlay notes, strings.
- [ ] **Step 4: Run** `scripts/npm.py test`, `run typecheck`, `run build`, `pytest tests/unit/test_web_strings.py tests/unit/test_i18n.py` — Expected: PASS. Browser check with the fake model (EN, AZ).
- [ ] **Step 5: Commit** `feat(ui): follow-up questions in the AI tab`

### Task 4: Real question, docs, final verification

- [ ] **Step 1:** one real question on the synthetic sample (owner's key, synthetic evidence only); record latency and whether citations validated.
- [ ] **Step 2:** README + CLAUDE.md.
- [ ] **Step 3:** full gates (ruff, mypy short path, full pytest, tsc, vitest, build, secret grep, LF check).
- [ ] **Step 4: Commit** `docs: AI follow-up questions`
