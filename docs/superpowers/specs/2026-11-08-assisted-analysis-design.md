# OctoV — Assisted malware analysis (design)

Date: 2026-11-08 · Status: draft for owner approval · Builds on: M1/M2 (`main` + PR #3, #4)

## 1. Intent

The owner wants OctoV to contain everything a malware analyst needs as a *base*
(the AI layer, M5, sits on top later), comparable in scope to what they do in
Ghidra, but **easier and clearer**, and **assisted rather than fully automatic**:

- the tool does the heavy, repetitive work as soon as a file is opened;
- the analyst stays in control: reviews, corrects, renames, drills down;
- it must **save time** for professionals and **teach** beginners.

Audience (owner's words): beginners in malware analysis *and* professionals who
need to save time. Neither group may be sacrificed for the other.

## 2. Goals, non-goals, anti-goals

**Goals**
1. Opening a sample yields, without further clicks, a *triage report*: risk score
   with its reasons, capabilities, IOCs, packer/obfuscation status, embedded
   payloads, ranked suspicious functions, ATT&CK mapping, YARA/Sigma.
2. Every automatic result is explainable: *what* was found, *where* (offset/RVA,
   clickable), *why it matters* (plain-language explanation, EN/AZ), and *what to
   look at next*.
3. The analyst can correct the machine: rename functions, comment, mark a
   finding as false positive / benign, bookmark. All of it persists in the
   `.octov` session and flows into exports (and later into the AI context).
4. Manual depth is available when needed: xrefs, strings, search, call graph,
   symbol tree, memory map, decompiled pseudo-C, data types (phased, see §6).
5. Works out of the box with the light core; heavy engines (capa, FLOSS,
   Ghidra decompiler) add depth when installed, without being required.

**Non-goals**
- Byte patching / assembling / rebuilding binaries (not needed for defence).
- An interactive debugger. Dynamic analysis is M3 (sandboxed tracing), not
  Ghidra's debugger.
- Collaboration server, multi-user projects.
- Replacing the analyst's judgement with a single "malicious/benign" verdict.

**Anti-goals** (would be a failure even if it technically works)
- A wall of unexplained numbers or flags that a beginner cannot act on.
- Automatic results that cannot be traced to evidence (every claim needs an
  offset/RVA, string, API or rule ID behind it).
- Slow first view: the analyst waits for heavy engines before seeing anything.
- Uploading samples or sending them anywhere; requiring internet.
- Making the UI harder for professionals (no forced wizards; keyboard first).

## 3. Constraints (already decided in this project)

- Local-only, offline, defensive scope; MIT licence; Windows 10/11 x64,
  Python ≥ 3.11 (dev on 3.12), uv.
- UI = React + TypeScript web UI in a pywebview / WebView2 window; the only
  UI↔core contract is `octov/app/api.py::WorkbenchApi` (JSON in/out).
- EN/AZ strings live in `octov/core/i18n/{en,az}.py`; a test enforces coverage.
- Severity guide: high = rare evasion artifact; medium = dual-use capability;
  low/info = weak signal. Baseline: 0 high hits on a Windows System32 sweep.
- Tests use synthetic benign samples only (`tests/samples/builder.py`).
- TDD, ruff, mypy strict, vitest, CI on windows-latest.

## 4. Approaches considered

| | Approach | Trade-off |
|---|---|---|
| A | Write everything ourselves (capabilities, string deobfuscation, decompiler) | Full control, fewest deps; slowest by far, decompiler quality would lag for a long time |
| B | Integrate proven engines directly (capa, FLOSS, Ghidra headless) as hard deps | Fastest to breadth, proven quality; heavy install (Java 21, ~500 MB), slow first run, harder for beginners |
| **C** | **Hybrid: light own core always on + heavy engines as auto-detected extensions** | Instant value and easy install, depth on demand; two layers (core + adapters) to maintain and test |

**Chosen: C** (owner picked it, accepting that it is a multi-phase project).
For the decompiler, C uses Ghidra headless (via `pyghidra`) as the extension; an
own decompiler stays a long-term option, not on this roadmap.

## 5. Architecture

### 5.1 Analysis pipeline

A sample is analysed by a sequence of **analyzers**. Each analyzer:

- declares `id`, `depends_on`, `cost` (`fast` | `slow`) and `requires`
  (extension name or `None`);
- reads the shared `AnalysisContext` (bytes, PE report, functions, xrefs, …)
  and writes typed results into it;
- emits **facts**: `{id, kind, severity, title_key, explain_key, evidence[],
  mitre[], tags[], confidence}`; `evidence` items carry offset/RVA/detail as the
  existing `Match` does.

Execution: all `fast` analyzers run synchronously in `open_sample` (budget
below); `slow` ones (function discovery, xrefs, capa, FLOSS, decompiler) run in
a background job queue per sample with progress reported through the existing
`discovery_status` mechanism, generalised to `job_status(sha)` returning one
entry per analyzer (`queued|running|done|failed|unavailable`, progress %).

Existing pieces become analyzers: PE parser indicators, rule engine, function
discovery. Results are stored in the session as they complete.

### 5.2 Extensions (adapters)

`octov/ext/{capa,floss,ghidra}.py`, each with `available() -> bool` (import /
binary probe, never network) and a `run(ctx)` that maps the engine's output into
OctoV facts. Installed as optional extras (`octov[capa]`, `octov[floss]`,
`octov[ghidra]`); the UI shows "enable" hints with the exact install command
when an extension is missing. All three are Apache-2.0 (compatible with MIT as
separately installed dependencies). Ghidra additionally needs a JDK 21 and a
Ghidra install path in `config.yaml` (`extensions.ghidra.install_dir`).

### 5.3 Analyst annotations

New session table `annotations(sha256, kind, address, value, created_at)` with
kinds `name`, `comment`, `bookmark`, `verdict` (on a fact: `false_positive`,
`benign`, `confirmed`). Annotations override automatic names in every view and
are included in exports. Undo = delete the annotation row (single-level is
enough for phase 1).

### 5.4 Risk score

Transparent and additive: each fact contributes `weight(severity, confidence)`;
facts marked false positive/benign by the analyst contribute 0. The report
shows the score *and* the list of contributions, so nobody has to trust a black
box. Bands: 0–29 low, 30–59 medium, 60–100 high (capped at 100).

### 5.5 Explanations (beginner support)

Each fact kind has `explain_key` → short paragraph in EN/AZ: what it is, why
attackers do it, what a benign program might do instead, what to check next.
UI: explanations shown inline but collapsible; a global "compact mode" toggle
for professionals hides them (persisted setting).

## 6. Phases

Each phase is its own branch + PR, shippable on its own.

**Phase 1 — Assisted triage core (light, no extensions).**
1. Strings analyzer: ASCII + UTF-16LE, min length 4, with section + offset/RVA;
   classifier for URL, IPv4/IPv6, domain, email, registry key, file path,
   mutex-like names, user-agent, base64 blob, command line / PowerShell,
   crypto-wallet; noise filter.
2. IOC list derived from (1) + imports, deduplicated, exportable (CSV/JSON/STIX
   later); private/reserved IPs and well-known benign domains marked as such.
3. Xrefs: code→code (calls/jumps, from CFG) and code→data (RIP-relative / absolute
   operands that point into sections: strings, IAT); "who uses this string/API".
4. Auto-naming: function names from strong evidence (export name, single
   dominant API family, e.g. `net_http_send`, `crypto_aes_wrapper`), always
   marked as *suggested* and overridable.
5. Crypto/compression constants (AES S-box, SHA-256 K, CRC32 table, RC4 KSA
   pattern, zlib, …) with location.
6. Embedded payloads: PE inside resources/overlay/sections (MZ+PE header scan),
   high-entropy resource blobs; listed with "open as new sample".
7. Packer view: existing indicators + entry-section entropy + import count into
   a single "packed?" verdict with reasons.
8. Function ranking: per function, suspicion score from APIs called, strings
   referenced, rule matches inside, crypto constants; top N in the report.
9. Risk score (§5.4) and the **Triage** screen (new first tab) as sketched:
   score + reasons, capabilities (rule/indicator based for now), IOCs, packer,
   embedded payloads, top functions with jump buttons, ATT&CK.
10. Annotations (§5.3) in disasm/graph/function list/findings; verdict buttons on
    facts; compact-mode toggle; explanations EN/AZ for every new fact kind.
11. Job queue + per-analyzer progress (§5.1).

**Phase 2 — Capabilities & strings depth (extensions).** capa adapter
(per-function capabilities with ATT&CK/MBC, merged into Triage and function
ranking); FLOSS adapter (stack/tight/decoded strings feeding the strings + IOC
analyzers).

**Phase 3 — Decompiler.** Ghidra headless adapter (`pyghidra`): pseudo-C per
function, cached in the session, synced with disasm/graph (address ↔ line),
annotations (names/comments) pushed into the decompiler output.

**Phase 4 — Navigation depth.** Symbol tree (imports/exports/functions/labels),
call graph (callers/callees, depth-limited), memory map view, search (bytes with
wildcards, strings, instruction text, immediates), Windows API prototypes for
call-site argument hints.

**Phase 5 — Knowledge & comparison.** Library function recognition (signature
DB, FLIRT-like, for MSVC CRT etc.) so analysts skip known code; PDB symbols from
the Microsoft symbol server + local cache; binary diff of two samples (function
matching, changed functions highlighted).

Then: M3 dynamic analysis, M5 AI assistant consuming facts + annotations.

## 7. Non-functional targets

- Phase 1 fast analyzers: < 3 s for a 5 MB sample on the dev machine; the Triage
  screen renders as soon as fast analyzers finish; slow ones stream in.
- System32 baseline: 0 *high* facts across all new analyzers.
- Every fact has ≥ 1 evidence item with offset or RVA (test-enforced).
- No new mandatory dependency heavier than a pure-Python wheel in phase 1.

## 8. Testing

Synthetic samples per analyzer (strings/IOCs, crypto tables, embedded PE,
xrefs); adapters tested with recorded engine output fixtures plus optional
integration tests that run only when the engine is installed; UI: vitest for
pure logic, manual check in the desktop window per phase.

## 9. Decisions made while writing this up (builder's calls, marked for owner review)

1. **Facts are the one result model.** Indicators and rule findings become facts;
   Findings/MITRE tabs, risk score and exporters all read facts. A fact marked
   *false positive* or *benign* is excluded from YARA/Sigma/IOC exports and from
   the score (still visible, greyed, with an "undo" button).
2. **Stable fact IDs.** `fact_id = <kind>:<rule-or-indicator id>:<primary location>`
   where the primary location is the lowest evidence RVA (or offset, or the string
   value for location-less facts). Facts are recomputed on reopen; verdicts are
   keyed by `fact_id`. A verdict whose fact no longer appears (e.g. rules changed)
   is kept and listed under "orphaned verdicts" instead of being silently dropped.
3. **Annotations always persist.** If no session is open, OctoV creates a per-sample
   workspace automatically (`~/.octov/workspaces/<sha256>.octov`) on the first
   annotation, so beginners never lose work. "Save session as…" copies it.
4. **Existing `notes` table is migrated** into `annotations(kind=comment)`; session
   schema v1 → v2 migration runs on open, with a test on a v1 fixture.
5. **Carved payloads stay inside the session** (stored as blobs with a parent→child
   link) and are never written to disk as executables. "Export payload" writes a
   password-protected ZIP (password `infected`, the industry convention), so no
   live PE lands on disk by accident.
6. **Raw (non-PE) mode in phase 1:** strings/IOCs, crypto constants, code→code
   xrefs, function ranking and risk score support raw blobs; PE-only analyzers
   (imports, resources, packer view, embedded PE in resources) report
   `unavailable` for raw input. Each analyzer has a raw test or an explicit skip.
7. **CLI parity:** `octov triage <file> [--json|--md] [--iocs out.csv]` prints the
   same triage report (score, reasons, capabilities, IOCs, top functions); the UI
   and CLI share one report builder.
8. **Risk score calibration target:** on the System32 baseline sweep, ≥ 95 % of
   binaries score *low* and none score *high*; the sweep test asserts both.
   *Amendment (owner, 2026-11-09):* each signal (fact kind + source) counts once, crypto
   constants count as one signal; three system binaries whose purpose matches the
   detectors (MRT.exe, services.exe, dbgeng.dll) are documented exceptions
   (`KNOWN_HIGH` in `tests/unit/test_baseline_fp.py`). All other files: none *high*.
9. **Decompiler:** the owner chose approach C with Ghidra headless as the
   decompiler extension; this supersedes the earlier CLAUDE.md note "MVP first
   (structured asm + CFG + type hints), pseudo-C later" (CLAUDE.md to be updated).

## 10. Left to the builder

Exact analyzer module layout; regexes and noise lists for the strings
classifier; weight tables for the risk score (documented in code); suspicion
heuristics for function ranking; Triage screen visual details within the
existing design system; job queue implementation (threads are fine).
