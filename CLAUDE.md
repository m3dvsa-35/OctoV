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
  core/export/              yara_gen.py, sigma_gen.py
  core/mitre.py             offline technique name/tactic table (test enforces coverage)
  core/session/session.py   .octov = SQLite + msgpack (samples, artifacts, notes, meta)
  app/api.py                WorkbenchApi: the ONLY UI<->core contract (JSON in/out)
  app/devserver.py          loopback RPC + static server (token, allowlist, no CORS)
  app/desktop.py            pywebview window; DesktopApi adds native file dialogs
  webui/dist/               built frontend (git-ignored)
web/src/                    React UI: api/client.ts (bridge or /rpc), state/store.ts,
                            components/* (Overview, Findings, Mitre, Disasm, Graph, Hex,
                            CommandPalette, Dialogs), lib/format.ts, lib/cfgLayout.ts
  cli/main.py               `octov analyze`
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

## Status / where we stopped

**M1 — done** (commit 965d7c2 on `main`, CI green).

**M2 — implemented on branch `feat/m2-static-engine`, PR open against `main`** (Issue #2):
- [x] Rule engine `core/static/rules.py` (bytes/string/import/export/section, any/all/N,
      `unless`; exporters of an API never count as its consumer).
- [x] Catalog tuned on System32: 0 high hits across 4370 binaries (full sweep:
      `OCTOV_FULL_BASELINE=1 pytest tests/unit/test_baseline_fp.py`, ~2 min).
- [x] Every catalog rule detects its synthetic sample (30/30) and respects its threshold.
- [x] Disassembler (`disasm.py`, Capstone `disasm_lite`, IAT annotation) + CFG (`cfg.py`,
      recursive descent, block splitting, seeds: EP/exports/.pdata).
      Timing: notepad 0.36 s, kernel32 1.5 s, shell32 13 s (20k-function cap).
- [x] Exporters `core/export/yara_gen.py` (compiles + matches sample, misses benign) and
      `sigma_gen.py` (pySigma-valid). CLI: `--yara`, `--sigma`, `--rules`, `--config`.
- [x] Pipeline `core/static/analysis.py` (`analyze`, `rule_set` cached; config `rules.paths`
      honoured by GUI and CLI).
- [x] GUI: Disassembly (+function list), native CFG graph (QGraphicsView — chosen over
      Cytoscape.js to stay offline/no bundled JS), Hex, MITRE heat table; background
      discovery (QThreadPool); synced navigation; LRU of 8 loaded samples.
- [x] Code review (9 findings) fixed with regression tests (`tests/unit/test_review_fixes.py`).
- [x] Raw (non-PE) input mode: `analyze_raw()`, `RawView` (32/64-bit), `discover_from()`,
      YARA without MZ anchor; CLI `--raw [--bits 32|64]` (Sigma refused for raw).
      GUI raw mode not done (the GUI is being replaced, see below).
- [ ] After PR merge: close #2, open M3 issue (dynamic analysis).

**GUI rewrite — branch `feat/web-ui` (stacked on `feat/m2-static-engine`), PR open:**
- [x] WorkbenchApi + dev server (tests: `test_app_api.py`), desktop shell (`octov-gui`).
- [x] React UI: samples/functions sidebar, Overview, Disassembly, CFG graph (React Flow + ELK
      worker, orthogonal edges), Hex (virtual, chunked), Findings, MITRE tiles, Ctrl+K palette,
      export dialog (YARA/Sigma), sessions, back/forward history, EN/AZ + Night/Normal.
- [x] Qt GUI and PySide6 removed.
- Next ideas: drag-and-drop open in desktop shell, AI panel (M5), dynamic views (M3).

Known limitation: tail jumps (`jmp` to another function) are followed as intra-function
edges, so CRT entry functions absorb their tail-called body.
