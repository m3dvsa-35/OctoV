# CLAUDE.md — OctoV working notes

Read this first in every session. Update the **Status / where we stopped** section at the end of
every milestone step (and before ending a session mid-step).

## What OctoV is

Defensive Windows binary analysis workbench (DFIR, detection engineering, threat hunting,
education). Analyses samples the user is authorised to examine and produces defender artifacts
(YARA, Sigma, STIX, IOCs). **No offensive capability** — never add code that injects, evades,
patches or weaponises. Everything runs locally; samples are never uploaded. The AI assistant only
ever receives extracted evidence, never the binary.

- Repo: https://github.com/m3dvsa-35/OctoV (public, MIT). Default branch `main`.
- Owner communicates in **Azerbaijani** — answer in Azerbaijani.
- Milestones are tracked as GitHub issues labelled `milestone` (#1 = M1 closed, #2 = M2).

## Decisions already made (do not re-ask)

| Topic | Decision |
|-------|----------|
| Python / packaging | 3.12 via uv (`requires-python >=3.11`), hatchling build |
| GUI | **Web UI** (React + TypeScript + Vite, Tailwind v4) in a pywebview / Edge WebView2 desktop window. Replaced PySide6 at the owner's request ("modern design, works well"). Two languages (EN/AZ) and two display modes (Night = neutral black like Claude Code, Normal = light), both as visible segmented switches |
| Dynamic (M3) | Frida 16.x pinned + frida-compile TS agent; Job Object + AppContainer (no admin) |
| Symbols | Microsoft Symbol Server + local PDB cache (`~/.octov/symbols`) |
| AI (M5) | OpenRouter `nvidia/nemotron-3-ultra-550b-a55b:free`; fallback any OpenAI-compatible endpoint (Ollama/LM Studio) |
| Decompiler | Ghidra headless via `pyghidra` as an optional extension (approach C, 2026-11-08); own decompiler = long-term option only |
| Telemetry | none |
| Test samples | synthetic & benign only (`tests/samples/builder.py`, `tests/samples/corpus.py`) |
| License | MIT |

| Product direction | Assisted (not fully automatic) malware analysis for beginners **and** pros: auto triage on open, every result explained (EN/AZ) and evidence-backed, analyst can correct. Design: `docs/superpowers/specs/2026-11-08-assisted-analysis-design.md` |

## Secrets

- AI key lives **only** in the user environment variable `OCTOV_AI_KEY` (already set on this
  machine). `config.py` ignores `api_key` in YAML. Never write a key into any file, commit, log or
  chat reply. `tests/unit/test_no_secrets.py` fails the suite if a key pattern appears in the repo.
  Before every push also run: `git grep -nE "sk-or-v1-[0-9a-f]{20,}"` (must print nothing).

## Environment quirks (this machine)

- `uv` is not on PATH: use `python -m uv ...`.
- The venv is `.venv` (Python 3.12.16). Run tools as `.venv/Scripts/python -m <tool>`.
- **mypy crashes from the long scratch path** (mypyc DLL, MAX_PATH). Run it via the 8.3 short path:
  ```powershell
  $s=(New-Object -ComObject Scripting.FileSystemObject).GetFolder((Get-Location).Path).ShortPath
  & "$s\.venv\Scripts\python.exe" -m mypy
  ```
- Bash heredocs containing non-ASCII text sometimes break — write such files with the Write tool.
- GUI screenshots: `QT_QPA_PLATFORM=offscreen` renders no fonts (boxes). Use the `windows`
  platform + `QTimer.singleShot(800, grab)` for visual checks.
- `git config core.autocrlf false` is set locally.
- No system Node.js: `nodejs-wheel-binaries` (dev dep) provides it; always run npm as
  `.venv/Scripts/python scripts/npm.py <args>` (cwd is switched to `web/`).
- Built UI goes to `src/octov/webui/dist/` (git-ignored). Rebuild after any `web/` change.
- Browser-pane screenshots can lag one frame or time out (a hidden pane is 0x0: virtualised
  lists render no rows until `resize_window`); verify DOM state with JS, and
  capture the desktop window with Win32 `PrintWindow(hwnd, hdc, 2)` (see session notes).

## Commands

```bash
.venv/Scripts/python -m ruff format . && .venv/Scripts/python -m ruff check .
<short-path python> -m mypy                      # strict, see quirk above
.venv/Scripts/python -m pytest -q                # QT offscreen is set in tests/conftest.py
.venv/Scripts/python -m octov.cli.main analyze C:\Windows\System32\notepad.exe
.venv/Scripts/python scripts/npm.py run typecheck   # web: tsc
.venv/Scripts/python scripts/npm.py test            # web: vitest
.venv/Scripts/python scripts/npm.py run build       # web -> src/octov/webui/dist
.venv/Scripts/python -m octov.cli.main serve        # UI in a browser (prints token URL)
.venv/Scripts/python -m octov.app.desktop [file]    # desktop window (octov-gui)
```

CI: `.github/workflows/ci.yml` — windows-latest; `python` job (3.11/3.12: ruff, mypy, pytest)
and `web` job (npm ci via nodejs-wheel, tsc, vitest, vite build).

## Layout

```
src/octov/
  core/config.py            YAML config + env key
  core/i18n/{en,az}.py      UI strings (same key set enforced by test)
  core/static/pe_parser.py  PEReport, hashes, sections, imports/exports, entropy, indicators
  core/static/rules.py      YAML rule engine (bytes/string/import/export/section, any/all/N, unless)
  core/static/analysis.py   analyze() = parse + rules; rule_set(paths) cached
  core/static/disasm.py     ImageView (RVA reads) + Disassembler (Capstone lite, IAT comments)
  core/static/cfg.py        build_function / discover_functions (basic blocks, edges)
  ext/                      optional engines: runner (Job Object, spawn_isolated), queue, cache,
                            capa_rules, capa, floss, apply (see Phase 2 notes)
  ext/ghidra/               decompiler: discover (JDK/Ghidra), setup, protocol, worker (the only
                            place pyghidra is imported; own process), manager, model
  core/apidoc.py            API -> `api.<Name>` explanation keys (texts: i18n/{en,az}_api.py)
  core/ai/                  AI analyst: bundle (evidence text + hash), client (OpenAI-compatible,
                            stdlib), report (prompt, parsing, citation checks)
  core/analysis/            triage pipeline: facts, pipeline, strings, iocs, xrefs, crypto,
                            carve, packer, naming, scoring, analyzers, report, callgraph, search
  core/export/              yara_gen.py, sigma_gen.py
  core/mitre.py             offline technique name/tactic table (test enforces coverage)
  core/session/session.py   .octov = SQLite + msgpack (samples, artifacts, annotations, payloads, meta; schema v2)
  app/api.py                WorkbenchApi: the ONLY UI<->core contract (JSON in/out)
  app/devserver.py          loopback RPC + static server (token, allowlist, no CORS)
  app/desktop.py            pywebview window; DesktopApi adds native file dialogs
  webui/dist/               built frontend (git-ignored)
web/src/                    React UI: api/client.ts (bridge or /rpc), state/store.ts,
                            components/* (Triage, Overview, Findings, Mitre, Disasm, Graph,
                            Relations, PseudoC, Hex, Strings, Search, Ai, MemoryMap, XrefPopover, AnnotateMenu,
                            CommandPalette, Dialogs),
                            lib/format.ts, lib/cfgLayout.ts, lib/triage.ts, lib/pseudoc.ts,
                            lib/relations.ts, lib/search.ts, lib/ai.ts
  cli/main.py, cli/triage.py `octov analyze`, `octov triage`
rules/                      evasion_patterns.yaml (EVA-xxx), pic_patterns.yaml (PIC-xxx)
tests/samples/builder.py    synthetic PE32+ builder (sections, imports, overlay, dll flag)
tests/samples/corpus.py     builds a sample per rule (detection-rate tests)
```

## Conventions

- **TDD**: write the failing test, watch it fail, then implement (superpowers TDD skill).
- ruff (line 100, `allowed-confusables = ["ı"]` for Azerbaijani) + mypy strict must stay clean.
- Every finding/indicator carries structured evidence (offset, RVA, API, section) — later AI
  reports must cite it; never invent offsets.
- Severity guide: `high` = rare evasion artifact (syscall stubs, reflective loader, kernel
  callback names); `medium` = capability via dual-use APIs; `low`/`info` = common/weak signal.
  Baseline: **0 high-severity hits on C:\Windows\System32** (re-check after rule changes).
- Import/string indicators never match a module that *exports* that API (kernel32, ntdll...).
- New UI text: add the key to both `en.py` and `az.py`; the web UI fetches them via
  `strings(lang)`. `tests/unit/test_web_strings.py` fails if a `t("key")` used in
  `web/src` is missing in either language.
- UI performance rules: virtualise long lists (`@tanstack/react-virtual`), fetch bytes in
  chunks, run ELK graph layout in its worker, keep store selectors shallow-stable.
- Never show meaning by colour alone (severity text, edge T/F labels + dash style).
- Commits: Conventional Commits, `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  Milestone work goes on a branch (`feat/m2-static-engine`) and lands through a PR.
- Installed plugins the user wants used: superpowers (TDD, verification, code review),
  caveman (commit messages, review), ui-ux-pro-max (visual panels), karpathy guidelines.

## Status / where we stopped  (updated 2026-11-14, chat 6)

### How to resume in a new chat (read this first)
1. `main` has M1, M2, web UI, assisted-triage Phases 1-2 (PR #6), Phase 3 Ghidra decompiler
   (PR #7), Phase 4 relations/search/symbols/file layout (PR #8), M5 AI analyst (PR #9) and
   **M5b AI follow-up questions (PR #10 merged as `d97eebe`)**. Each PR description lists its
   rulings and deferred minors.
2. **Nothing is in progress and nothing is designed for the next step.** This note is only on
   the local branch `docs/status-m5b-merged` (one commit on top of `main`, not pushed; the
   repo was left checked out on it): create the next feature branch from it so the note
   travels along. **When the owner writes "davam et" in a new chat:**
   a. `git status -sb && git log --oneline -3` (expect `docs/status-m5b-merged`, clean except
      the two stray files below).
   b. Ask what is next, recommending one (nothing is designed yet): **Phase 5** (FLIRT-like
      library-function recognition so analysts skip known code, PDB symbols from the Microsoft
      symbol server, binary diff of two samples) or **M3 dynamic analysis** (Frida 16.x,
      Job Object + AppContainer; a much bigger and riskier step). Builder's recommendation:
      Phase 5, starting with library recognition.
   c. The owner usually answers "do what is needed": then the builder designs and builds
      (spec -> plan -> inline execution with `superpowers:executing-plans` -> fresh opus
      review -> one fix pass -> PR -> ask about Auto-fix -> merge only after the owner's yes),
      stating decisions instead of asking, except choices about what leaves the machine
      (owner's option B for AI: evidence incl. pseudo-C and strings may be sent, but it is
      shown and confirmed before every send; one chosen destination, no automatic fallback).
   Open questions for the owner (asked several times, never answered): may the two stray files
   `src/octov/ext/ghidra/manager (1).py` / `worker (1).py` be deleted (see "Other open work");
   delete the merged remote branches (`feat/decompiler-phase3`, `feat/relations-phase4`,
   `feat/ai-m5`, `feat/ai-chat` and older ones)?
   Still open: deferred minors of PRs #7-#10; the follow-up question box and AZ were not
   looked at in the desktop (pywebview) window (the other new tabs were, on 2026-11-13, with a
   throwaway script: `DesktopApi` with temp settings + `webview.start(driver)` +
   `window.evaluate_js`).
   Working rules learned the hard way: stage files explicitly (never `git add -A` or
   `git add src`); piping a gate into `tail` hides its exit code, read the output before
   committing; the full pytest suite takes ~10 min, run it in the background; bash heredocs
   mangle backslash escapes inside generated code, use the Write/Edit tools for those; UI
   checks never touch `~/.octov/ui.json` (throwaway server with temp settings).
3. Owner priorities (2026-11-10): fast and trouble-free, PE files first, help beginners;
   later AI must show visually what it found suspicious and how parts are linked. Roadmap:
   Phase 4 relations/call graph (symbol tree, memory map, search) -> M5 AI overlay.
4. Engines on this machine: capa 10.0.0 (rules v10.0.0 + sigs), FLOSS 3.2.0, pyghidra 3.2.0,
   Ghidra 12.2 at `~/.octov/ghidra/12.2/ghidra_12.2_PUBLIC`, JDK 25.0.1 at
   `C:\Program Files\Eclipse Adoptium\jdk-25.0.1.8-hotspot` (PATH java is 8, ignored).
5. `python -m uv sync` sometimes fails with "Access is denied" removing
   `.venv/Lib/site-packages/octov-0.1.0.dist-info` — delete that folder (PowerShell
   `Remove-Item -Recurse -Force`) and rerun.
6. `git push` may hang in git-credential-manager (sign-in window): push with
   `git -c credential.helper= -c "credential.helper=!gh auth git-credential" push`.

### AI analyst — M5 facts worth knowing
- `core/ai/bundle.py`: `build_bundle(BundleInput, budget_chars)` -> `Bundle(doc, text, hash,
  omitted, fact_ids, functions, iocs)`; `text` is the preview and the request, byte for byte.
  `core/ai/client.py`: `endpoints(cfg)` (the destinations to choose from; the key only goes to
  its own remote host), `chat` (stdlib urllib, no redirects, https or loopback http only,
  `AIError(kind)`; there is deliberately no automatic fallback); `core/ai/report.py`: `system_prompt(lang)`,
  `parse_report(text, bundle)` (drops citations that are not in the bundle), `cited_functions`.
- API: `ai_status()`, `ai_preview(sha)` (text, hash, `endpoints`), `ai_analyse(sha,
  confirmed_hash, force, endpoint)` (one destination, chosen by index),
  `get_ai_report(sha)` (newest report + `stale`); `job_status()["ai"]`; errors `ai.no_endpoint`, `ai.preview_changed`,
  job errors `ai.<kind>`; cache `~/.octov/cache/<sha>/ai-<model>-<bundle hash>.json.gz`.
  The newest report is also kept as `ai-last-none.json.gz`: when the evidence changes
  (engines finishing, renames, verdicts) it stays visible with `stale: true`.
- Web: tab `ai` (`AiView.tsx`, `lib/ai.ts`), store `aiReport` + `loadAiReport`, overlay in
  `RelationsView.tsx` (AI marks, dashed arcs), a line in Triage.
- Follow-up questions (M5b): `core/ai/chat.py` (`compose(bundle, question, history, focus)`
  -> one user message = preview = request; `parse_answer`; `Turn`), API `ai_chat_preview(sha,
  question, focus)`, `ai_ask(sha, question, confirmed_hash, focus, endpoint)`,
  `get_ai_chat(sha)`, `clear_ai_chat(sha)`, `job_status()["ai_chat"]`; store
  `ai-chat-none.json.gz` (max 50 turns, last 6 sent); one AI request per sample (`ai.busy`).
  Web: `AiChat.tsx` inside the AI tab, store `aiChat`. First real question (2026-11-14,
  synthetic injector, focus on the entry function): 4 149 characters, 21.6 s, all citations valid.
- Tests use `tests/fixtures/fake_llm.py` (in-process server on 127.0.0.1); never the network.
- First real runs (2026-11-13, synthetic injector, OpenRouter
  `nvidia/nemotron-3-ultra-550b-a55b:free`): 3 979 characters sent; EN answer in 26.5 s, AZ in
  44.9 s; both parsed, assessment "malicious / high", every citation valid, 1 statement
  dropped. Only synthetic evidence was sent.
- UI check: throwaway script with `FakeLLM` as `config.ai.base_url` + `make_server`.

### Navigation — Phase 4 facts worth knowing
- `core/analysis/callgraph.py`: `CallGraph.build(functions, xrefs)` (direct calls + tail jumps
  to another function), `neighbourhood(center, callers_depth, callees_depth, max_nodes=60)`
  (level by level, callee side first; `hidden_callers/hidden_callees`, `truncated`),
  `path_to(center, roots)`, `apis_of(xrefs, start)`. Built lazily, cached on `_Sample`.
- `core/analysis/search.py`: `parse_pattern`, `parse_number`, `search_bytes`, `search_text`,
  `search_immediate` (limit + truncated flag).
- API: `get_relations(sha, start, callers=2, callees=2)`, `search(sha, kind, query, limit)`
  (`kind` = `bytes|text|imm`), `get_symbols(sha)`, `get_memory_map(sha)`; error keys
  `analysis.not_ready`, `search.bad_pattern`, `search.bad_number`. No new facts or scores.
- Web: tabs `relations` (`RelationsView.tsx`, `lib/relations.ts`) and `search`
  (`SearchView.tsx`), sidebar Symbols (`Sidebar.tsx`, `lib/search.ts`), `MemoryMap.tsx` in
  Overview; the shared ELK worker is `components/elk.ts`; tab bars scroll horizontally.
- Speed (2026-11-10): twinui.dll (18 551 functions) relations 100 ms first / 1.3 ms warm, hub
  with 6 351 callers 1.9 ms; byte search 2-36 ms, text 977 ms, constant 1005 ms. amdhip64.dll
  (18.5 MB, 20 000 functions): 87 / 1.0 ms, bytes 7-146 ms, text 1187 ms, constant 1221 ms.
- UI check without touching `~/.octov/ui.json`: a throwaway script that builds `WorkbenchApi`
  with temp `settings_path` (all `extensions_auto_run` off) and `make_server(api, DIST, port)`.

### Decompiler — Phase 3 (Ghidra) facts worth knowing
- `octov/ext/ghidra/`: `discover` (JDK >= 21 from `release` files, Ghidra 12.x, status),
  `setup` (pinned zip), `protocol` (JSON lines, `GhidraError`), `worker` (child process, the
  only pyghidra import; stdout is the protocol, JVM output goes to stderr), `manager`
  (`GhidraWorker`, `GhidraManager`: one `open` at a time app-wide, `max_workers`, crash ->
  restart once then `failed`, request timeout -> kill, no retry, sample stays usable; idle
  reaper; `cleanup_projects`), `model` (`DecompiledFunction`, `annotation_hash`, `line_marks`).
- API: `get_decompiled(sha, rva)`, `job_status()["ghidra"]`, `run_extension(sha, "ghidra",
  force)`, `shutdown()`; settings `extensions_auto_run.ghidra`. Error messages are i18n keys
  (`decomp.no_function`, `decomp.analysing`, `decomp.not_ready`, `decomp.timeout`,
  `decomp.failed: <detail>`). Pseudo-C cache: `~/.octov/cache/<sha>/ghidra-<ver>-<annotation
  hash>/<entry>.json.gz`; entry point + top 10 ranked functions are decompiled ahead.
- **Ghidra refuses a project path with an element starting with "."** -> saved projects are in
  `%LOCALAPPDATA%\OctoV\ghidra-projects` (not `~/.octov`, a deviation from the design).
- Unit tests use `tests/fixtures/fake_ghidra_worker.py` and the conftest stub of
  `api.ghidra_status`; two real-Ghidra tests run only when Ghidra + JDK + pyghidra are present
  (~25 s each). The full suite takes ~9 min on this machine (real capa/FLOSS/Ghidra tests).
- Speed (`scripts/ghidra_speed.py`, 2026-11-10, System32): analysis 25 s (50 KB), 37 s
  (0.3 MB), 94 s (1 MB), 224 s (5 MB twinui.dll), 306 s (10 MB wmp.dll), 354 s (18.5 MB); reopen from
  the saved project 8-13 s; decompile p50 0.29-0.31 s, p95 0.35-2.4 s; cached p50 5-6 ms.
- Memory: the Job limit (`max_memory_mb`, 4096) covers Python + JVM; the JVM heap is 5/8 of
  it (`heap_mb`). With 3584 or 3072 MB heap wmp.dll killed the JVM at the limit during a full
  GC. JVM crash reports go to `%TEMP%\octov-ghidra-hs_err_pid*.log`.
- A project is reused only if `octov-analysed.ok` exists in it (written after the analysed
  program was saved); otherwise it is deleted and analysed again.
- The triage CLI and `scripts/baseline_sweep.py` switch Ghidra off (it adds no facts and no score).
- Web: tab id `pseudo_c` (`PseudoCView.tsx`, helpers `lib/pseudoc.ts`); API hover texts come
  from the `api.<Name>` strings (127 APIs, EN/AZ, test-enforced coverage).
- Known gap (pre-existing, Phase 2 runner): a process exiting in the middle of spawning an
  engine can leave a suspended child outside its Job Object (seen with a throwaway script).

### Assisted triage — Phase 2 (capa + FLOSS) facts worth knowing
- `octov/ext/`: `__init__` (status probe, never imports engines), `runner` (child process in a
  Job Object: memory limit, kill-on-close, below-normal priority, timeout, cancel), `queue`
  (one capa + one FLOSS process app-wide; dedupe per opened-sample object), `cache`
  (`~/.octov/cache/<sha>/<engine>-<ver>-<rules>.json.gz`), `capa_rules` (pinned rules zip +
  3 FLIRT .sig files, sha256), `capa`, `floss`, `apply` (merge + rerun iocs / naming+ranking).
- **Calibration result:** capa `MEDIUM_PREFIXES = ("communication/c2",)`. Every other
  candidate namespace (keylog, anti-VM, stack strings, persistence, RWX/inject, impact)
  matched benign System32 components (Magnify, Narrator, msctf, dxgi, services) and pushed
  them to the high band (83-file run: 83 % low, 4 high). capa matches are otherwise `info`
  (explained, used for ranking reasons). `hidden_ioc` (FLOSS) stays medium, one per sample.
- Confirming sweep (199 files, every 22nd System32 file, both engines, final scoring): 98.49 % low (196), 3 medium, 0 high band, 0 high-severity facts; capa done on 189 (10 timeouts), FLOSS done on 177 (22 timeouts); median capa 43 s / FLOSS 70 s, p90 209 s / 315 s.
- **Engine speed:** vivisect is slow on big DLLs: 2–6 min for 2–7 MB files, some hit the
  600 s timeout (they end `failed`, by design). Small files: seconds. The first view never
  waits; results are cached.
- Unit tests never use the machine's engines (`tests/conftest.py` stubs `extension_status`);
  `tests/unit/conftest.py` has the `engines` fixture (fake engine printing recorded fixtures).
  Real-engine integration tests are skipped unless capa/FLOSS are installed.
- Session calls are serialized by an RLock (concurrent writes on one sqlite3 connection lost
  rows); every job ends in `done|failed|unavailable|idle`.

### Assisted triage — Phase 1 (branch `feat/assisted-triage`)
Spec: `docs/superpowers/specs/2026-11-08-assisted-analysis-design.md` (owner-approved).
Plan: `docs/superpowers/plans/2026-11-08-assisted-triage-phase1.md` (14 tasks, all done).

Modules: `core/analysis/{facts,pipeline,strings,iocs,xrefs,crypto,carve,packer,naming,scoring,
analyzers,report}.py`; session schema v2 (`annotations`, `payloads`, v1 auto-migrates);
`cli/triage.py` (`octov triage`); EN/AZ explanations for every fact kind; web UI tabs
`Triage | Overview | Disassembly | Graph | Hex | Strings`, xref popover, annotate menu
(`n` rename, `;` comment, `b` bookmark, `x` xrefs, or right-click), Compact toggle
(`settings.compact`).

Key interfaces (stable, use these names):
- `facts.Fact(kind, source_id, severity, title, evidence, mitre, tags, confidence, explain_key)`,
  `.id` = `kind:source_id:<lowest rva|offset hex|value>`; `facts.Evidence(detail, offset, rva, type, value)`.
- `pipeline.AnalysisContext` + `Pipeline(analyzers).run_fast(ctx)` / `.start_slow(ctx, on_done)` /
  `.status()`; fast = pe_indicators, rules, strings, iocs, crypto, carve, packer;
  slow = functions → xrefs → naming → ranking.
- `WorkbenchApi`: `get_triage, job_status, get_strings, get_iocs, export_iocs, xrefs_to, annotate,
  delete_annotation, list_annotations, set_verdict, list_payloads, open_payload, export_payload`;
  `get_settings/set_settings` include `compact: bool`.
- Annotations live in the open session, else in `~/.octov/workspaces/<sha256>.octov`
  (SQLite opened with `check_same_thread=False`: the dev server/pywebview call from worker threads).
- Web: `api.getStrings` (not `strings`, which fetches UI text), store actions `renameFunction`,
  `setComment`, `toggleBookmark`, `promptAnnotation`, `annotationKey`; helpers in `web/src/lib/triage.ts`.

Baselines (Windows 11 System32, 4370 files, 2026-11-09, `scripts/baseline_sweep.py`):
rules-only 0 high hits; full pipeline 0 high facts, 0 failed jobs, 0 timeouts, 99.08 % low
(4330 low / 37 medium / 3 high). High band = only the owner-approved `KNOWN_HIGH` files
(MRT.exe 88, services.exe 68, dbgeng.dll 64). Before the signal dedupe (`1bbd994`) it was
98.8 % low with 5 high (also whesvc_assets.dll, ntoskrnl.exe). Timing: fast analyzers median
0.11 s / p99 1.06 s / max 27 s (amd_comgr.dll, 100 MB); slow analyzers median 0.41 s /
p99 22.5 s / max 50 s.
Perf: synthetic 5 MB PE, fast analyzers 0.7 s (budget 3 s, `tests/unit/test_triage_perf.py`).
CI runs a System32 slice (stride 25 for rules, stride 80 for the full pipeline, ~45 s).

Known limitations: tail jumps are followed as intra-function edges (CRT entry functions absorb
their tail-called body); the Strings tab has no chip for uncategorised strings ("All" only).

### Other open work
- Phase 2 deferred minors: listed in PR #6's description and its ledger.
- Re-run the engine calibration with
  `scripts/baseline_sweep.py out.jsonl --ext --stride 22 --cache-dir ~/.octov/calib-cache`
  (~1.5 h; the cache makes reruns after scoring changes fast).
- Remote branches `feat/m2-static-engine`, `feat/web-ui`, `feat/assisted-triage`,
  `feat/decompiler-phase3` are merged and
  can be deleted (not done: the owner did not ask).
- Roadmap: Phase 5 (FLIRT-like, PDB, binary diff); M3 dynamic; AI guided workflows.
- Two untracked copies `src/octov/ext/ghidra/manager (1).py` and `worker (1).py` (old
  snapshots, appeared 2026-11-10 12:02, not made by Claude) break local ruff/mypy; run
  `ruff ... "--extend-exclude=* (1).py"` until the owner removes them.
- Phase 3 not done: desktop-window (pywebview) visual check of the Pseudo-C tab; it was
  checked in the browser pane (`octov serve`) in EN and AZ with real Ghidra.

### Environment notes learned in chats 1-2
- Bash heredocs that contain `\0`/`\x00`/`\\` escapes can be mangled. For non-trivial edits
  use the Write/Edit tools, or a Python script that edits with `read_bytes`/`write_bytes`.
- **`Path.write_text` on Windows writes CRLF** — the repo is LF. Use `write_bytes` (or
  `newline="\n"`). Check before committing: `git ls-files --eol | grep w/crlf` must print nothing.
- Desktop window screenshot: `PrintWindow(hwnd, hdc, 2)` via PowerShell Add-Type; the window
  handle is `(Get-Process python | ? MainWindowTitle -eq "OctoV").MainWindowHandle`.
  The UI settings file is `~/.octov/ui.json` (language/theme/compact) — set it before launching
  to capture other languages/modes, and restore it afterwards.
- Interactive UI checks are easiest in the browser pane: `octov serve --port 8765`, open the
  printed token URL, drive the page with JS (React inputs need the native value setter).
- In chat 2 the project folder had lost `.git` and `.venv` (it was a copy). `.git` was restored
  from a fresh clone after verifying identical content; git identity is set **repo-locally**
  (`m3dvsa-35`, noreply address). Recreate the venv with `python -m uv sync --all-extras` and
  web deps with `scripts/npm.py ci`.
- Rebuild the web UI after any `web/` change before testing the desktop app.
