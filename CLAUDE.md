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
- Browser-pane screenshots can lag one frame or time out; verify DOM state with JS, and
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
  ext/                      optional engines: runner (Job Object), queue, cache, capa_rules,
                            capa, floss, apply (see Phase 2 notes)
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
                            Hex, Strings, XrefPopover, AnnotateMenu, CommandPalette, Dialogs),
                            lib/format.ts, lib/cfgLayout.ts, lib/triage.ts
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

## Status / where we stopped  (updated 2026-11-09, chat 4)

### How to resume in a new chat (read this first)
1. `main` has M1, M2, web UI and assisted-triage Phase 1 (PRs #3/#4/#5 merged).
2. **Phase 2 (capa + FLOSS) is implemented on `feat/assisted-triage-phase2`** and pushed;
   its PR targets `main` (see "Other open work"). Owner was away and said "do what is needed,
   don't wait for approval": the PR was opened but **not merged** — merging is the owner's call.
   Design: `docs/superpowers/specs/2026-11-09-assisted-triage-phase2-design.md`; plan:
   `docs/superpowers/plans/2026-11-09-assisted-triage-phase2.md` (13 tasks, all done);
   ledger: `.superpowers/sdd/2026-11-09-assisted-triage-phase2/progress.md` (rulings + deferred
   minors). Final review: 0 Critical, 4 Important (+1 re-graded) fixed in `36fcd24`.
3. Engines on this machine: `octov ext status` → capa 10.0.0 (rules v10.0.0 + sigs) and
   FLOSS 3.2.0 ready (`python -m uv sync --all-extras`, `octov ext setup capa`).
4. Next: owner reviews/merges the Phase 2 PR, then Phase 3 (Ghidra decompiler) — start with
   `superpowers:brainstorming` against the parent spec's Phase 3.

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
- Phase 2 PR (`feat/assisted-triage-phase2` → `main`): open, not merged. Deferred minors are
  listed in its description and the ledger.
- Calibration sweep numbers with engines: see the PR description / ledger (200-file slice,
  `scripts/baseline_sweep.py --ext --stride 22 --cache-dir ~/.octov/calib-cache`).
- Remote branches `feat/m2-static-engine`, `feat/web-ui`, `feat/assisted-triage` are merged and
  can be deleted (not done: the owner did not ask).
- Roadmap: Phase 3 (Ghidra decompiler), Phase 4 (symbol tree,
  call graph, memory map, search), Phase 5 (FLIRT-like, PDB, binary diff); M3 dynamic; M5 AI.

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
