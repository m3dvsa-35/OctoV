# OctoV — Phase 3: Ghidra decompiler extension (design)

Parent spec: `2026-11-08-assisted-analysis-design.md` (approach C, §5.2, §6 Phase 3).
Phases 1 and 2 are merged into `main`. Status: draft for owner review.

## 1. Intent

The owner's product goal (2026-11-10, in their words, translated): malware should be easy to
analyse **without AI** — relations, functions, imports, strings, disassembly — and **with AI**
the tool should show visually what the AI found suspicious, where, and which parts are related
and malicious. Conditions: the program must be **fast and trouble-free**, focus on **PE files**,
and **help beginners** in malware analysis.

Phase 3 adds readable code: a pseudo-C view of each function from Ghidra's decompiler, synced
with disassembly and graph. It serves both halves of the goal:

- without AI, analysts (and beginners especially) read C far more easily than assembly, and
  OctoV marks the lines that matter (suspicious API calls, data behind findings) with an
  explanation;
- with AI (M5, later), decompiled functions are the evidence the AI reads best, and its
  findings will point at pseudo-C lines; Phase 4's call graph becomes the canvas on which
  AI-flagged functions and their links are shown.

Order chosen by the builder (owner delegated): Phase 3 decompiler → Phase 4 relations / call
graph → M5 AI visual overlay.

## 2. Goals, non-goals, anti-goals

**Goals**
1. With Ghidra available, every OctoV function (and any address inside a Ghidra function) can
   be shown as pseudo-C within ~1 s after the background analysis finished; the most suspicious
   functions (Phase 1 ranking) are decompiled in advance.
2. Two-way sync: the current address highlights its pseudo-C lines; clicking a line moves
   disassembly/graph to its address.
3. Analyst names and comments appear in the pseudo-C (callers show renamed callees too);
   suggested names are applied as well.
4. Beginner help without AI: lines calling APIs from OctoV's suspicious API families or
   touching evidence of a fact get a marker with the fact/explanation; hovering an API name
   shows a short EN/AZ explanation of what it does.
5. Reopening a sample does not redo Ghidra's analysis (saved Ghidra project + per-function
   pseudo-C cache).
6. Without Ghidra, OctoV works exactly as today; the UI says what the decompiler adds and how
   to enable it.

**Non-goals**
- Editing types/structures in Ghidra from OctoV, patching, re-compiling.
- Raw shellcode in Phase 3 (owner: focus on PE) — raw samples report `unavailable`.
- Storing pseudo-C in `.octov` sessions (builder's call, see §5.4).
- .NET (IL), ELF, Mach-O.
- Our own decompiler.

**Anti-goals**
- The first view waits for Ghidra, or the UI freezes while Ghidra works.
- Ghidra (JVM) memory or a crash affects OctoV.
- The app downloads anything by itself (installs are explicit CLI steps).
- Pseudo-C shown as a wall of code with no guidance for a beginner.
- A stale pseudo-C view after a rename (names out of sync between views).

## 3. Constraints

Parent spec §3 holds (local-only, MIT, Windows, Python ≥ 3.11, WorkbenchApi is the only
UI↔core contract, EN/AZ coverage test, synthetic test samples, TDD/ruff/mypy strict/vitest/CI).

Facts checked 2026-11-10: Ghidra 12.2 (`ghidra_12.2_PUBLIC_20261016.zip`, 569,712,708 bytes,
Apache-2.0) needs a JDK ≥ 21; `pyghidra` 3.2.0 (PyPI, deps JPype1, packaging) starts the JVM
inside a Python process. On the owner's machine `java` on PATH is Java 8 (too old) while
`C:\Program Files\Eclipse Adoptium\jdk-25.0.1.8-hotspot` is installed — the JDK must be found
without relying on PATH. Phase 2's process isolation (Job Object runner, queues, cache layout,
`octov ext` CLI, engine cards) is reused.

## 4. Approaches considered

| | Approach | Trade-off |
|---|---|---|
| **1** | **One long-lived Ghidra worker process per open PE sample** (pyghidra, JSON-lines over stdin/stdout): import + auto-analysis in the background on open, then decompile on demand; top functions decompiled in advance; Ghidra project saved per sample | Fastest interaction, renames applied live; worker lifecycle (start, restart, shutdown) to manage |
| 2 | One-shot batch child: import, analyse, decompile every function to JSON, exit | Simple; minutes before the first function on big binaries, renames need a full re-run |
| 3 | Ghidra `analyzeHeadless` with a post-script per request | Ghidra-native, no pyghidra; a JVM start per call (slowest) |

**Chosen: 1** (builder's call; the owner's condition "fast and trouble-free" decides it).

Ghidra install: `octov ext setup ghidra` downloads the pinned Ghidra 12.2 zip once (sha256),
or `--from-zip PATH`, or an existing install via `extensions.ghidra.install_dir`; the JDK is
found by the rules in §5.2 or set with `extensions.ghidra.java_home`.

## 5. Design

### 5.1 Status and setup (`octov/ext/ghidra/`)

- `GhidraStatus`: installed = `pyghidra` importable (find_spec) + a Ghidra install directory
  (config `extensions.ghidra.install_dir`, else `~/.octov/ghidra/<version>/`, else
  `GHIDRA_INSTALL_DIR`) + a JDK ≥ 21. Any Ghidra **12.x** is accepted (version read from
  `Ghidra/application.properties`); other versions report `ext.reason.ghidra_version`.
  Reasons: `ext.reason.not_installed`, `ext.reason.no_ghidra`, `ext.reason.no_jdk` (with the
  found Java version), `ext.reason.ghidra_version`.
- `octov ext setup ghidra [--from-zip PATH]`: pinned URL + sha256, safe extraction (same rules
  as the capa rules installer), into `~/.octov/ghidra/12.2/`. ~570 MB: the CLI prints the size
  before downloading. The sha256 is taken from Ghidra's release page and pinned in code. `pyghidra` comes with the extra `octov[ghidra]`.
- `octov ext status` lists ghidra with its JDK.

### 5.2 Finding the JDK

Order: config `extensions.ghidra.java_home`; `JAVA_HOME` if it is ≥ 21; newest JDK ≥ 21 under
`C:\Program Files\{Eclipse Adoptium,Java,Microsoft,Zulu,Amazon Corretto}\`; `java` on PATH if
≥ 21. Version read from the `release` file (`JAVA_VERSION="25.0.1"`), never by running Java in
the UI process. The worker is started with `JAVA_HOME` set to the chosen JDK.

### 5.3 Worker process

- Started from the engine runner's Job Object (memory limit `extensions.ghidra.max_memory_mb`,
  default 4096; the JVM gets `-Xmx` a bit below it), below-normal priority, kill-on-close.
- One worker per open PE sample, at most `extensions.ghidra.max_workers` (default 2) at a time;
  further samples wait (`queued`). Only **one** first-time analysis runs at a time app-wide, so
  Ghidra never competes with itself (capa/FLOSS keep their own queues). Auto-run follows the
  Phase 2 per-engine setting (`extensions_auto_run.ghidra`, default on). Closing a sample stops its worker. Idle workers stop after
  `idle_minutes` (default 10) and restart on demand from the saved project (seconds).
- Protocol: JSON lines. Requests: `open` (sha256, bytes as base64, project dir),
  `decompile` (address, names, comments), `functions` (Ghidra's function list, for mapping),
  `shutdown`. Responses carry an id; every
  request has a timeout (`decompile_timeout_s`, default 30).
- Import + auto-analysis on first open (timeout `analysis_timeout_s`, default 900); the Ghidra
  project is saved to `~/.octov/ghidra-projects/<sha256>/` so later opens only load it. The
  saved project always stays **exactly as auto-analysis left it** (builder's call): analyst
  names and comments are applied per `decompile` request inside a transaction that is rolled
  back, never saved. So two sessions with different names for the same sample, and undo
  (deleting an annotation), stay correct. `rename`/`comment` requests are therefore not needed.
- The sample's bytes are sent to the worker over the pipe and imported from memory (a Ghidra
  byte provider), never written to disk as an executable — this also makes **carved PE
  payloads** decompilable (they stay in memory per Phase 1's rule). Projects older than
  `project_keep_days` (default 30, by last use) are deleted on startup.
- A crashed worker is restarted once automatically; a second crash marks the job `failed`
  with the reason (UI shows "Run again").

### 5.4 Decompiled function model

`DecompiledFunction(entry_rva, name, code: str, lines: list[Line], warnings)`, where
`Line(text, rvas: tuple[int, ...])` lists the instruction addresses Ghidra attributes to that
line (from its token/address map). Pseudo-C lives only in the machine-local cache, not in
`.octov` sessions (builder's call: no session schema change, sessions stay small; a colleague
without Ghidra re-runs it or installs Ghidra). This amends the parent spec's "cached in the
session". Cache: `~/.octov/cache/<sha>/ghidra-<ver>-<annot hash>/
<entry>.json.gz` — the annotation hash covers the names/comments that affect the output, so a
rename invalidates exactly what it must. Requests for an address inside a function decompile
the containing Ghidra function; OctoV and Ghidra function boundaries may differ (OctoV's
tail-call limitation): the view always shows Ghidra's function and says which OctoV function
the address belongs to.

### 5.5 Beginner guidance in the pseudo-C (no AI)

- A line is **marked** when it calls an import in OctoV's suspicious API families (Phase 1
  `naming.API_FAMILIES` / `SUSPICIOUS_FAMILIES`) or when one of its addresses is evidence of a
  fact (rule, indicator, capability, hidden IOC…). The marker shows severity as text + icon
  (never colour alone) and links to the fact and its EN/AZ explanation.
- Hovering a Windows API name shows a one-line EN/AZ description ("WriteProcessMemory — writes
  into another process's memory; used for process injection"). The table covers every API in
  `API_FAMILIES` plus the APIs used by the indicator rules (test-enforced coverage).
- A short "How to read this" help (EN/AZ, collapsible, hidden in Compact mode) explains
  pseudo-C conventions (`param_1`, `local_10`, `DAT_…`, `FUN_…`).

### 5.6 API and UI

- API: renames/comments only invalidate the affected cache entries (annotation hash);
  `get_decompiled(sha, rva) -> {entry_rva, name, lines:[{text, rvas, marks:[fact ids]}],
  warnings, octov_function}`; `job_status` gains `ghidra` (analysis state, elapsed, cached);
  renames/comments in OctoV are forwarded to the worker (debounced) and invalidate the cache.
- UI: a new code view **Pseudo-C** (main and side panel tabs, next to Disassembly/Graph).
  Virtualised lines (long functions), monospace, syntax colouring, current-address lines
  highlighted, click a line → navigate to its first address, markers in the gutter, API hover.
  While Ghidra analyses: a progress state with elapsed time; if Ghidra is missing: the engine
  card (what it adds, commands).
- Triage "Most suspicious functions": a "Pseudo-C" jump next to each function.

### 5.7 Speed budget

- First view of a sample: unchanged (Ghidra never in the fast lane).
- After analysis: decompile of an uncached function ≤ 1 s typical (30 s hard timeout), cached
  ≤ 50 ms; the 10 top-ranked functions are decompiled right after analysis.
- Reopen: project load instead of analysis (target ≤ 15 s to ready for a 5 MB PE).

## 6. Testing

- Unit: JDK discovery (fake directory trees with `release` files), status reasons, setup
  (zip-slip, sha256, `--from-zip`), protocol client against a **fake worker** (a Python script
  speaking the same JSON-lines protocol: replies, delays, crashes, timeouts), line→address
  mapping, markers, cache invalidation by annotation hash, worker limits/idle stop/restart.
- Integration (skipped unless Ghidra + JDK + pyghidra are present): decompile the synthetic
  injector sample; renamed function appears in the caller's pseudo-C.
- UI: vitest for line/marker helpers; manual desktop check EN/AZ, Night/Normal.
- Baseline: the System32 sweeps are unaffected (Ghidra adds no facts and no score); a speed
  check records analysis and decompile times on a handful of System32 PEs of different sizes.

## 7. Left to the builder

Exact pyghidra calls and Ghidra API for tokens→addresses; worker script layout; the API
description table wording; syntax colouring details within the design system; numbers for
timeouts/limits within the ranges above after measuring.
