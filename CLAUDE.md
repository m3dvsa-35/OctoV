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
  core/analysis/            triage pipeline: facts, pipeline, strings, iocs, xrefs, crypto,
                            carve, packer, naming, scoring, analyzers, report
  core/export/              yara_gen.py, sigma_gen.py
  core/mitre.py             offline technique name/tactic table (test enforces coverage)
  core/session/session.py   .octov = SQLite + msgpack (samples, artifacts, annotations, payloads, meta; schema v2)
  app/api.py                WorkbenchApi: the ONLY UI<->core contract (JSON in/out)
  app/devserver.py          loopback RPC + static server (token, allowlist, no CORS)
  app/desktop.py            pywebview window; DesktopApi adds native file dialogs
  webui/dist/               built frontend (git-ignored)
web/src/                    React UI: api/client.ts (bridge or /rpc), state/store.ts,
                            components/* (Triage, Overview, Findings, Mitre, Disasm, Graph,
                            PseudoC, Hex, Strings, XrefPopover, AnnotateMenu, CommandPalette, Dialogs),
                            lib/format.ts, lib/cfgLayout.ts, lib/triage.ts, lib/pseudoc.ts
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

## Status / where we stopped  (updated 2026-11-10, chat 5)

### How to resume in a new chat (read this first)
1. `main` has M1, M2, web UI, assisted-triage Phase 1 and Phase 2 (capa + FLOSS, PR #6
   merged as `332e457`).
2. **Phase 3 (Ghidra decompiler) is implemented on `feat/decompiler-phase3`** (all 9 plan
   tasks, final review + one fix pass done, pushed, PR to `main` open). **Do not merge
   without the owner's yes.** Design: `docs/superpowers/specs/2026-11-10-decompiler-phase3-design.md`;
   plan: `docs/superpowers/plans/2026-11-10-decompiler-phase3.md`. The PR description lists
   the rulings (deviations) and the deferred minors.
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
- Remote branches `feat/m2-static-engine`, `feat/web-ui`, `feat/assisted-triage` are merged and
  can be deleted (not done: the owner did not ask).
- Roadmap: Phase 4 (symbol tree, call graph, memory map, search), Phase 5 (FLIRT-like, PDB,
  binary diff); M3 dynamic; M5 AI.
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
