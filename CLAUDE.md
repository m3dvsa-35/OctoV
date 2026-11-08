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
| GUI | PySide6, dockable panels, dark/light themes, EN/AZ i18n |
| Dynamic (M3) | Frida 16.x pinned + frida-compile TS agent; Job Object + AppContainer (no admin) |
| Symbols | Microsoft Symbol Server + local PDB cache (`~/.octov/symbols`) |
| AI (M5) | OpenRouter `nvidia/nemotron-3-ultra-550b-a55b:free`; fallback any OpenAI-compatible endpoint (Ollama/LM Studio) |
| Decompiler (M4) | MVP first (structured asm + CFG + type hints), pseudo-C later |
| Telemetry | none |
| Test samples | synthetic & benign only (`tests/samples/builder.py`, `tests/samples/corpus.py`) |
| License | MIT |

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

## Commands

```bash
.venv/Scripts/python -m ruff format . && .venv/Scripts/python -m ruff check .
<short-path python> -m mypy                      # strict, see quirk above
.venv/Scripts/python -m pytest -q                # QT offscreen is set in tests/conftest.py
.venv/Scripts/python -m octov.cli.main analyze C:\Windows\System32\notepad.exe
```

CI: `.github/workflows/ci.yml` — windows-latest, Python 3.11 + 3.12, ruff + mypy + pytest.

## Layout

```
src/octov/
  core/config.py            YAML config + env key
  core/i18n/{en,az}.py      UI strings (same key set enforced by test)
  core/static/pe_parser.py  PEReport, hashes, sections, imports/exports, entropy, indicators
  core/static/rules.py      YAML rule engine (bytes/string/import/export/section, any/all/N, unless)
  core/session/session.py   .octov = SQLite + msgpack (samples, artifacts, notes, meta)
  gui/main_window.py        dock shell; DOCK_IDS; load_sample(); attach_session()
  gui/theme.py              QSS palettes + severity colours
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
- New UI text: add the key to both `en.py` and `az.py`.
- Commits: Conventional Commits, `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  Milestone work goes on a branch (`feat/m2-static-engine`) and lands through a PR.
- Installed plugins the user wants used: superpowers (TDD, verification, code review),
  caveman (commit messages, review), ui-ux-pro-max (visual panels), karpathy guidelines.

## Status / where we stopped

**M1 — done** (commit 965d7c2 on `main`, CI green).

**M2 — in progress** on branch `feat/m2-static-engine` (Issue #2):
- [x] Rule engine `core/static/rules.py` + tests (`tests/unit/test_rules.py`); every catalog rule
      detects its synthetic sample (100%) and respects its threshold.
- [x] Catalog tuned against System32 (export suppression, severity re-grading, longer patterns).
- [ ] Verify full System32 scan has 0 high hits (rules + parser indicators).
- [ ] Capstone disassembly + function discovery + CFG (`core/static/disasm.py`, `cfg.py`).
- [ ] Raw shellcode (non-PE) input mode.
- [ ] Exporters: YARA (+ compile check with yara-python), Sigma (+ pySigma validation).
- [ ] GUI panels: Disassembly, Graph (Cytoscape.js in QWebEngineView), Hex, MITRE heatmap; synced nav.
- [ ] Wire findings into CLI output, GUI indicators table and sessions.
- [ ] Code review, update this file, push branch, open PR, close #2 after merge.
