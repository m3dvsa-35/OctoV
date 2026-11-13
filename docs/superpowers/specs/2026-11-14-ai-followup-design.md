# OctoV — M5b: follow-up questions to the AI analyst (design)

Parent: `2026-11-11-ai-overlay-m5-design.md` (its non-goal "free-form chat / follow-up
questions" is this step). M5's first slice is merged. Status: builder's design; the owner
picked the feature ("AI chat") and keeps their earlier decision: **everything that is sent is
shown before every send and confirmed each time** (option B).

## 1. Intent

The report answers "what is this?". A beginner's next questions are specific: "why is this
function suspicious?", "what does this string mean?", "what should I look at next?". Today
they would have to ask again for a whole new report. Follow-up questions let the analyst ask
in their own words, about the same evidence, and get a short, cited answer.

## 2. Goals, non-goals, anti-goals

**Goals**
1. A question box in the AI tab; answers appear as a conversation under the report, each with
   evidence chips (functions, findings, IOCs) that navigate, in the UI language.
2. "About the current function": one switch adds the function the analyst is looking at
   (name, APIs, callers/callees, strings, code) to the question, so it can be asked about
   even if it is not among the top-ranked functions of the bundle.
3. Before every send the analyst sees the **whole message** verbatim (evidence, the focus
   function, the earlier questions and answers that are included, the new question), its size
   and destination, and confirms that one send. What is sent is exactly what was shown.
4. Citations in answers are checked like in the report: unknown ids/addresses/IOCs are
   removed and counted.
5. The conversation is kept per sample (machine-local cache) and can be cleared.

**Non-goals**: tool-calling / the model fetching more data by itself, streaming, the model
editing names/verdicts, conversations shared in `.octov` sessions, more than one conversation
per sample.

**Anti-goals**: anything sent that the preview did not show; a question changing what counts
as evidence; help with building, improving or hiding malware (the system prompt forbids it;
OctoV is defensive).

## 3. Constraints

- Reuses M5: `Bundle`, `client.chat`, `endpoints`, the confirmation-by-hash pattern, no
  automatic fallback, key rules, cache module. No new dependency.
- One request at a time per sample (shared with the report request).
- Bounded: question ≤ 1 000 characters; the last 6 turns are included, each answer cut to
  1 500 characters in the message; everything after the evidence ≤ 8 000 characters
  (older turns are left out first, then the focus function's code is cut).

## 4. Approaches considered

- **A. One composed user message per question (chosen)**: evidence + focus + history +
  question in a single text. The preview is that text, so "sent = shown" is trivial to prove
  and to test, and it works with every OpenAI-compatible model. Costs: the evidence is resent
  with each question (bounded, and visible).
- **B. Real multi-turn message list** (bundle once, then alternating roles). Slightly cheaper
  for some providers, but the preview would have to render a message list and the hash a
  structure; more surface for "sent differs from shown".
- **C. Tool-calling agent** that pulls functions on demand: the model decides what leaves the
  machine, which contradicts the owner's confirm-each-send decision.

## 5. Design

### 5.1 `core/ai/chat.py`

- `Turn(question, answer, functions, findings, iocs, dropped, model, host, created)`.
- `compose(bundle, question, history, focus) -> ChatMessage(text, hash, known_functions)`:
  sections in fixed order with plain headers — `EVIDENCE` (bundle.text), `FUNCTION IN FOCUS`
  (JSON like a bundle function, only when given and not already in the bundle), `EARLIER
  QUESTIONS AND ANSWERS` (last 6), `QUESTION`. `hash` = sha256 of the text (16 hex).
- `chat_system_prompt(lang)`: same rules as the report prompt (untrusted evidence, cite only
  what is there, defensive only) + "answer the QUESTION briefly for a beginner" + the answer
  schema `{"answer": str, "functions": [addr], "findings": [id], "iocs": [value]}`.
- `parse_answer(text, bundle, extra_functions) -> Answer`: tolerant JSON extraction (reuses
  the report's); a reply that is not JSON is accepted as plain text with no citations (a
  chat answer is still useful as prose); citations validated; answer cut at 4 000 chars.
- `validate_question(text)`: stripped, 1..1 000 chars, else `ValueError`.

### 5.2 API

- `ai_chat_preview(sha, question, focus=None)` -> `{text, chars, hash, endpoints}`.
- `ai_ask(sha, question, confirmed_hash, focus=None, endpoint=0)`: recomposes; a different
  hash -> `ai.preview_changed` and nothing is sent; background job `job_status["ai_chat"]`;
  on success the turn is appended to `~/.octov/cache/<sha>/ai-chat-none.json.gz`.
- `get_ai_chat(sha)` -> `{turns: [...]}`; `clear_ai_chat(sha)`.
- Errors: `ai.bad_question`, `ai.no_endpoint`, `ai.preview_changed`, `analysis.not_ready`;
  job failures `ai.<kind>`.

### 5.3 UI (AI tab)

Under the report (or under the first preview when there is no report yet): the conversation
(question, answer, chips, model · host), then the question box with the "about the current
function (name)" switch and "Preview". Preview shows the whole message + destination +
"Send this to <host>" / Cancel. While waiting: a status line. "Clear conversation" with a
confirmation. Errors as text. Functions cited in answers also get the AI mark on the
Relations graph (notes = the answer's first sentence).

## 6. Testing

Unit: compose (order, focus only when needed, history cap, cut answers, hash changes with
any part), question validation, answer parsing (JSON, prose, bad citations, focus function
citable), API with the fake server (sent == previewed, wrong/stale hash sends nothing, turn
stored and returned, history included next time, clear, failure states, focus function
outside the bundle), vitest for the turn/notes helpers. Browser check with the fake model.

## 7. Left to the builder

Prompt wording, exact section headers, chip layout, where the question box sits.
