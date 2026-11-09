# OctoV — Assisted triage Phase 2: capa + FLOSS extensions (design)

Parent spec: `2026-11-08-assisted-analysis-design.md` (approach C, §5.2 extensions, §6 Phase 2).
Phase 1 is merged into `main` (PR #5). Status: draft for owner review.

## 1. Intent

Phase 1 gives every sample an explained triage report from OctoV's own light
analyzers. Its capability view is shallow: it only knows imports, byte rules and
a handful of indicators, and it only sees strings that sit in the file as plain
text. Malware routinely hides both: behaviour behind generic APIs, and strings
(C2 URLs, mutex names, registry keys) built on the stack or decoded at run time.

Phase 2 adds the two proven open-source engines that close those gaps, as
**optional extensions**:

- **capa** (Mandiant, Apache-2.0): ~1000 community rules that recognise
  behaviours per function ("encrypt data using AES", "inject thread",
  "check for debugger via API"), with ATT&CK and MBC tags.
- **FLOSS** (Mandiant, Apache-2.0): recovers obfuscated strings: stack strings,
  tight strings and strings decoded by a decoding routine (emulated).

For a beginner, the Triage tab then shows *what the program does* in named
behaviours and the hidden IOCs; for a professional, capa matches land on
functions (ranking, names) and decoded strings land in the Strings tab with the
routine that decoded them.

The owner chose the build approach by delegating it ("whichever works best");
every call below is marked as the builder's call for review.

## 2. Goals, non-goals, anti-goals

**Goals**
1. With capa installed, its matches become OctoV facts (kind `capability`) with
   evidence (function RVA + match locations), ATT&CK/MBC, and an EN/AZ
   explanation; they appear in Triage, Findings, MITRE, the score and the
   function ranking, and analysts can mark them like any other fact.
2. With FLOSS installed, stack/tight/decoded strings join the Strings tab
   (marked with their origin and the function that produced them) and feed the
   IOC analyzer; hidden IOCs become facts.
3. Without the engines OctoV works exactly as today and the UI says, per engine,
   what it would add and the exact command to enable it.
4. Engine results are cached per sample, so reopening a sample does not rerun
   minutes of analysis.

**Non-goals**
- Our own capability engine or string emulator (approach A was rejected).
- capa/FLOSS for .NET or ELF (capa supports them; OctoV is Windows-PE/shellcode).
- Editing or authoring capa rules in the UI.
- Fixing all Phase 1 deferred minors (separate cleanup), except the two
  concurrency races that the extension thread makes more likely (§5.9).

**Anti-goals**
- The first view waits for capa/FLOSS (they run minutes on large files).
- The app touches the network (the rules download is an explicit CLI step).
- A crash, hang or memory blow-up in an engine takes OctoV down or freezes the UI.
- A carved payload is written to disk as an executable just to scan it.
- ~1000 English rule names shown to an AZ beginner with no explanation.
- The System32 calibration (spec §9.8) regresses because capa flags common
  behaviour as medium.

## 3. Constraints

Everything in the parent spec §3 still holds (local-only, MIT, Windows,
Python ≥ 3.11, WorkbenchApi is the only UI↔core contract, EN/AZ coverage test,
severity guide, synthetic test samples only, TDD/ruff/mypy strict/vitest/CI).

Engine facts (checked 2026-11-09 on PyPI): `flare-capa` 10.0.0 and
`flare-floss` 3.2.0, both Apache-2.0, `requires-python >= 3.10`, both built on
`vivisect` (pure Python; correct but slow, minutes on large binaries). Both resolve
together with OctoV's dependencies on Python 3.11 and 3.12 (`uv pip compile`),
so one venv and `sys.executable` work. The capa
pip package is expected **not** to ship the rules (separate `capa-rules`
repository); the builder verifies this against the installed wheel first and
drops the setup step if a matching rule set is bundled.

## 4. Approaches considered

**Engine integration**

| | Approach | Trade-off |
|---|---|---|
| **1** | **Run each engine as a child process (`-j` JSON output), parse the result document** | Crash/memory isolation, hard timeout and cancel, UI never blocks; a few hundred ms start-up per run |
| 2 | Call the engines in-process as libraries | Slightly faster, shares memory; a stuck vivisect run cannot be killed and competes with the UI process |
| 3 | Feed capa from OctoV's own disassembly (custom feature extractor, no vivisect) | Fast, consistent with our views; large effort, rule-match fidelity risk; FLOSS still needs vivisect |

**Chosen: 1** (builder's call, owner delegated).

**capa rules delivery**

| | Approach | Trade-off |
|---|---|---|
| A | Vendor a pinned rules snapshot into the repo | Works offline at once, deterministic; ~5 MB of third-party YAML in the repo, updates by PR |
| **B** | **`octov ext setup capa` downloads a pinned rules release once, verifies its sha256, unpacks to `~/.octov/capa-rules/<version>/`** | Repo stays light; needs internet once, at the same moment the extension itself is installed; analysis stays offline |

**Chosen: B** (proposed by the builder, owner said "whichever works best").
`--from-zip <path>` supports air-gapped machines.

## 5. Design

### 5.1 Extension framework (`octov/ext/`)

`octov/ext/__init__.py` defines:

- `ExtensionStatus(id, installed, ready, version, rules_version, reason_key,
  install_cmd, setup_cmd)`. `installed` = the engine package is importable
  (probe with `importlib.util.find_spec`, never importing vivisect into the UI
  process); `ready` = installed and (for capa) a rule set is present.
- `extension_status() -> list[ExtensionStatus]`, cached until settings change.
- Per-engine settings (persisted with the UI settings, shown in the engine
  card): `auto_run` (default on when ready). When off, the engine runs only
  from an explicit "Run" action.
- `octov/ext/capa.py`, `octov/ext/floss.py`: each builds the command line, runs
  it, parses the JSON and maps it to OctoV results (below).

`pyproject.toml` gains extras `capa = ["flare-capa>=10,<11"]` and
`floss = ["flare-floss>=3.2,<4"]` (major versions pinned because we parse their
JSON). They stay out of the default dependency set.

### 5.2 Running an engine

- Command: `[sys.executable, "-m", <engine module>, "-j", ...]` using the same
  interpreter, so it works in the venv without PATH lookups. The exact module
  and flags are verified against the installed versions by the builder.
- Input: the sample's original file path. Samples with no real file behind
  them (carved payloads opened from a parent) report `unavailable`
  (reason "in-memory sample"); they are **not** written to disk (anti-goal).
- Raw shellcode: capa `-f sc32|sc64`, FLOSS `--format sc32|sc64` by `bits`.
- Limits (config `extensions.<id>.timeout_s`, default 600;
  `extensions.<id>.max_size_mb`, default 64): a larger file reports
  `unavailable` (reason "too large, raise max_size_mb"); a timeout reports
  `failed` (reason "timed out after N s").
- The child runs at below-normal priority inside a Windows Job Object with a
  memory limit (`extensions.<id>.max_memory_mb`, default 4096; exceeding it
  ends as `failed`, reason "memory limit"). Closing the sample or the app
  terminates it (the job kills the process tree).
- **One global queue per engine:** at most one capa and one FLOSS process run
  at a time in the whole app, whatever the number of open samples; waiting
  samples show `queued`. Closing a sample removes its queued jobs. stdout is read fully; stderr is kept (last
  4 KB) for the failure reason.
- No network: the child gets no extra environment beyond the parent's.

### 5.3 Pipeline: a separate extension lane

A third cost class `"extension"` is handed to the global engine queues (§5.2)
after the fast analyzers, in parallel with each sample's existing slow lane
(functions → xrefs → naming → ranking). Order inside the lane: FLOSS, then
capa (strings are cheaper and feed IOCs sooner). The core slow lane is never
delayed by an engine.

When an extension result arrives, the dependent core results are recomputed:
FLOSS → IOCs (and their facts) over the union of static and recovered strings;
capa → naming and ranking (cheap, they already exist as analyzers). The UI
refreshes the report each time **any** job finishes (today it waits for all
jobs, which would hold back the slow-lane results for minutes).

`job_status` entries gain `elapsed_s` and `cached` (bool). Neither engine
reports progress in its JSON mode, so the UI shows an indeterminate spinner
with elapsed time instead of the spec's "progress %" (builder's call).

### 5.4 Cache

Engine output is a machine-local cache, not analyst work, so it lives in
plain files, not in session files:
`~/.octov/cache/<sha256>/<engine>-<engine_version>-<rules_version>.json.gz`
(the raw JSON, gzip). On open, a file matching the installed engine and rules
versions is loaded instead of rerunning (status `done`, `cached: true`). This
works the same with or without an explicit session, keeps shared `.octov`
files small, and needs **no session schema change**. Writes are atomic
(temp file + rename). A "Re-run" action ignores and replaces the cache.

### 5.5 capa → facts, ranking and names

- Only top-level rule matches become facts; `lib` rules and rules capa marks
  as subscope-only are skipped (they are building blocks).
- Fact: `kind="capability"`, `source_id=<rule name>`, evidence = one item per
  match location (VA → RVA via the image base; the containing function is the
  primary location), `mitre` = the rule's ATT&CK ids, `tags` = MBC ids and the
  rule namespace.
- Severity (builder's call, calibrated in §6): a benign DLL typically matches
  20–40 capa rules, so capa facts are **`info` by default** (listed, explained,
  0 points). A short curated list of namespace prefixes that rarely appear in
  benign software (`host-interaction/process/inject`, `persistence/`,
  `collection/keylog`, `anti-analysis/anti-vm`, `anti-analysis/obfuscation`,
  `impact/`, `communication/c2`) → `medium`; the list lives in code and is the
  only knob §6 tunes. capa facts are **never** `high`. Each rule name scores
  once (Phase 1 signal dedupe). A capa rule that restates an OctoV fact (e.g.
  "check for debugger via API" next to `anti_debug_apis`) stays `info`.
- Function boundaries: capa/FLOSS addresses are mapped onto the OctoV
  function that contains them (`FunctionIndex.lookup`); OctoV's function list
  is never extended by an engine. A match outside every OctoV function keeps
  its address as evidence and simply has no function badge/ranking entry.
- Ranking: each function gets the points of its capa facts (same weights as
  other facts) and the rule names as reasons.
- Naming: a function whose capa matches include exactly one medium rule gets a
  suggested name from that rule (`inject_thread_401000`); otherwise the Phase 1
  API-family name stays. Analyst names always win.
- Explanations: one EN/AZ paragraph per top-level namespace (~20:
  anti-analysis, collection, communication, data-manipulation, executable,
  host-interaction, impact, linking, load-code, persistence, runtime, targeting
  …), keys `capa.ns.<namespace>.explain`; the rule name itself is shown in
  English with its namespace. The i18n test enforces both languages.

### 5.6 FLOSS → strings and IOCs

- `FoundString` gains `origin: "static" | "stack" | "tight" | "decoded"` and
  `function: int | None` (the function that builds or decodes it). Recovered
  strings have no file offset; their evidence is the function RVA (stack/tight)
  or the decoding routine and call site (decoded).
- FLOSS's own static strings are ignored (OctoV already extracts them);
  recovered strings identical to a static one are dropped.
- Strings tab: an "origin" column and an "Obfuscated" chip; a recovered
  string's xrefs point at its function. `get_strings` gets an `origin` filter.
- IOCs: built over static + recovered strings; an IOC found only in recovered
  strings is tagged `hidden`.
- Facts: `obfuscated_strings` (low) when FLOSS recovers ≥ 5 strings, evidence =
  the producing functions; `hidden_ioc` (medium) listing the hidden URL/IP/domain/mutex/wallet/command
  IOCs as evidence: **one fact per sample** (one signal, scores once, however
  many hidden IOCs). Both get EN/AZ explanations.

### 5.7 UI

- Triage: the job chips show `capa` / `floss` with state, elapsed time and
  "cached"; a missing or not-ready engine shows a short card: what it adds
  (EN/AZ), the exact commands (`uv sync --extra capa`,
  `octov ext setup capa`) with a copy button, and nothing else (no download
  button: the app stays offline).
- Capabilities card: capa facts grouped by namespace with counts; each row has
  jump, verdict buttons and the collapsible explanation (Compact hides it).
- Function list: a small capa count badge (text, not colour only); the ranking
  card lists capa reasons.
- Strings tab: origin column + "Obfuscated" chip (§5.6).
- A "Re-run" item per engine (in the chip's menu) ignores the cache; when
  `auto_run` is off the same menu offers "Run". The engine card carries the
  `auto_run` switch.

### 5.8 CLI

- `octov ext status`: table of engines, versions, rules version, ready/why.
- `octov ext setup capa [--from-zip PATH]`: downloads the pinned `capa-rules`
  release matching the installed capa major (URL + sha256 pinned in code),
  rejects archive entries escaping the target directory, unpacks to
  `~/.octov/capa-rules/<version>/`. With `--from-zip`, no network.
- `octov triage` waits for extension jobs too (same timeouts); `--no-ext`
  skips them.

### 5.9 Concurrency fixes carried in

The extension thread adds concurrent access to a sample, so the two Phase 1
deferred races are fixed here: `_open_bytes` and `_store(create=True)` do their
check-then-act under the API lock (one pipeline and one workspace connection
per sample, never two).

## 6. Calibration and baseline

capa on all 4370 System32 files would take many hours, so the baseline uses a
deterministic **slice of 200 files** (every 22nd) with both engines, run by an
extended `scripts/baseline_sweep.py --ext`. Targets: 0 *high* facts, ≥ 95 %
low band, high band only `KNOWN_HIGH`. If capa pushes files up, the severity
mapping in §5.5 is tuned (not the band thresholds). The rules-only and core
full-pipeline sweeps over all files stay as in Phase 1. CI runs no engines.

## 7. Testing

- Unit tests parse **recorded JSON fixtures** (trimmed engine output produced
  by running the engines on synthetic builder samples and one benign System32
  file; never malware) and check facts, evidence RVAs, severities, ranking,
  names, strings/IOC merge and cache round-trips.
- Runner tests use a fake engine module (a tiny Python script that prints
  canned JSON, sleeps, or crashes) to test timeout, failure reason, cancel on
  close, size limit and the in-memory-sample rule without installing anything.
- Integration tests run only when an engine is installed (skipped otherwise).
- `ext setup`: zip-slip, wrong sha256 and `--from-zip` tests with local zips
  (no network in tests).
- UI: vitest for grouping/filter helpers; manual desktop check (EN/AZ,
  Night/Normal) with and without the engines.

## 8. Non-functional targets

- First Triage view time unchanged with engines installed (they never run in
  the fast lane).
- Reopening a sample with cached engine results shows them within the fast-lane
  budget (< 3 s for 5 MB).
- Engine failures never surface as an unhandled error; each ends as
  `failed`/`unavailable` with a readable reason.

## 9. Left to the builder

Exact engine CLI modules/flags and JSON field paths for the pinned majors;
rules release URL and hash; the list of namespaces with explanations; the
severity mapping details within §5.5's rule (tuned by §6); fixture contents;
visual details of the engine card within the existing design system.
