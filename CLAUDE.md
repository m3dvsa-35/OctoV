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

## Status / where we stopped  (updated 2026-11-08, end of chat 1)

### How to resume in a new chat (read this first)
1. `git switch feat/assisted-triage && git pull` — all work is pushed.
2. Work is executed **inline ("Native")** with the superpowers *executing-plans* skill
   (owner chose it). Invoke `superpowers:executing-plans` with
   `docs/superpowers/plans/2026-11-08-assisted-triage-phase1.md`, then continue at the
   first task without a `complete` line in the ledger.
3. Ledger (git-ignored, local only): `.superpowers/sdd/2026-11-08-assisted-triage-phase1/progress.md`
   — contains pre-flight table, every `Ruling:` and `Task N: complete` lines. If it is missing
   (fresh clone), trust `git log` (one `feat(analysis): ...` commit per task) and recreate it.
4. Helper scripts (absolute paths on this machine):
   `C:/Users/Fexreddin/.claude/plugins/cache/superpowers-dev/superpowers/7.0.2/skills/executing-plans/scripts/task-start <PLAN_ABS> <N>`
   and `.../task-done <PLAN_ABS> <N> <BASE_SHA> -- <test command>` (run with `bash`).
5. Per task: write the failing test, run it (must fail), implement, run, ruff format+check,
   commit (`feat(analysis): ...` + Co-Authored-By trailer), `task-done`. Then next task.
6. After Task 14: final whole-branch review (`superpowers:requesting-code-review` style,
   fresh subagent on the most capable model), ONE fix pass, then push + PR + update this file.

### Assisted triage — Phase 1 progress (branch `feat/assisted-triage`)
Spec: `docs/superpowers/specs/2026-11-08-assisted-analysis-design.md` (owner-approved).
Plan: `docs/superpowers/plans/2026-11-08-assisted-triage-phase1.md` (14 tasks).

| # | Task | State | Module(s) |
|---|------|-------|-----------|
| 1 | Fact model + analyzer pipeline | done | `core/analysis/facts.py`, `pipeline.py` |
| 2 | Strings extraction + classification | done | `core/analysis/strings.py` |
| 3 | IOC list (CSV/JSON) | done | `core/analysis/iocs.py` |
| 4 | Instruction.data_ref + XrefIndex | done | `core/static/disasm.py`, `core/analysis/xrefs.py` |
| 5 | Crypto constants | done | `core/analysis/crypto.py` |
| 6 | Embedded payload carving + AES ZIP | done | `core/analysis/carve.py` (dep `pyzipper`) |
| 7 | Packer verdict + suggested names | done | `core/analysis/packer.py`, `naming.py` |
| 8 | Function ranking + risk score | done | `core/analysis/scoring.py` |
| 9 | Session schema v2 (annotations, payloads, migration) | done | `core/session/session.py` |
| 10 | Analyzers + API integration + triage report | done | `core/analysis/analyzers.py`, `report.py`, `app/api.py` |
| 11 | CLI `octov triage` | done (`cli/triage.py`) | `cli/main.py` |
| 12 | Explanations EN/AZ for fact kinds | done | `core/i18n/{en,az}.py` |
| 13 | Web UI: Triage, Strings, xrefs, annotations, compact | **PARTIAL — NEXT** | `web/src/...` |
| 14 | Baseline/perf tests + docs | todo | tests, CLAUDE.md, README |

Key interfaces already built (use these exact names in Tasks 8-14):
- `facts.Evidence(detail, offset=None, rva=None, type=None, value=None)`;
  `facts.Fact(kind, source_id, severity, title, evidence, mitre=(), tags=(), confidence=1.0,
  explain_key=None)` with `.id` = `kind:source_id:<lowest rva|offset hex|value>`, `.to_dict()`;
  `facts_from_indicators(report)`, `facts_from_findings(findings)`.
- `pipeline.AnalysisContext(data, report, bits, findings, functions={}, index=None,
  results={}, facts=[])` + `.add(facts)`; `Analyzer` protocol (`id, cost "fast"|"slow",
  depends_on, pe_only, run(ctx)`); `Pipeline(analyzers).run_fast(ctx)`,
  `.start_slow(ctx, on_done)`, `.status()` → `{id: {"state","error"}}`.
- `strings.FoundString(value, encoding, offset, rva, section, category)`,
  `extract_strings(data, report, min_len=4)`, `classify(value)`, `MAX_STRINGS`.
- `iocs.Ioc(type, value, offsets, benign_hint)`, `build_iocs(strings)`, `iocs_csv`, `iocs_json`.
- `xrefs.Xref(src, dst, kind, func)`, `XrefIndex.build(functions, import_addresses)`,
  `.to(dst)`, `.from_function(start)`, `.imports_called(start)` → `["dll!func"]`.
- `crypto.find_crypto(data, report)` → facts kind `crypto_constant`.
- `carve.Payload(offset, size, kind, where, sha256)`, `carve_payloads(data, report)`,
  `payload_facts(payloads)`, `payload_zip(data, name)` (AES, password `infected`).
- `packer.PackerVerdict`, `packer_verdict(report)`, `packer_fact(report, verdict)`.
- `naming.API_FAMILIES`, `suggest_name(start, imports_called)`.
- `scoring.risk_score(facts, verdicts)` → `RiskScore(score, band, contributions)`;
  `rank_functions(functions, xrefs, facts, strings, names)` → `[RankedFunction(start, name, score, reasons)]`.
- `Session.add_annotation(sha, kind, value, address=None, target=None)`, `.annotations(sha, kind=None)`,
  `.delete_annotation(id)`, `.add_payload(parent, payload, data)`, `.payload_bytes(sha)`, `.payloads(parent)`;
  schema v2 (`annotations`, `payloads`), v1 auto-migrates.
- `analyzers.default_analyzers()`; `report.build_triage(ctx, verdicts, names, jobs)` → dict keys
  score, packer, capabilities, iocs, payloads, top_functions, attack, orphaned_verdicts, jobs.
- `WorkbenchApi(config, settings_path, workspace_dir)`: new `get_triage, job_status, get_strings,
  get_iocs, export_iocs, xrefs_to, annotate, delete_annotation, list_annotations, set_verdict,
  list_payloads, open_payload, export_payload`; `get_findings` rows are fact dicts (+name,
  description, mitre_names, rva, offset, verdict; display `source_id`, not `id`);
  `list_functions` items have `suggested`. Frontend not yet updated for these (Task 13).

### Task 13 status
DONE: types/client use the fact shape (`FindingRow`, `CapabilityRow`, `Triage`), Findings/Overview
show `source_id`, new **Triage** tab (default; `TriageView.tsx`) with score + reasons, verdict
buttons, packer, capabilities with EN/AZ explanations, IOCs + CSV copy, top functions, payload
open/encrypted export; store polls `job_status` and refreshes triage (`refreshAnalysis`, `setVerdict`).
LEFT: Strings tab (`api.get_strings` paging, category chips, xref count), xref popover
(`xrefs_to`), rename/comment/bookmark actions in disasm/graph/function list (`annotate`,
`list_annotations`), Compact toggle (+ `compact` in get/set_settings), desktop visual check of
the Triage tab in both languages/modes. Then Task 14 and the final review.

### Notes for Task 13 (web UI)
- Backend is complete; the frontend still speaks the *old* findings shape. Breaking change:
  `get_findings` rows now have `id` = fact id (`rule:EVA-001:0x2000`), `source_id` (show this in
  the ID column), `kind` (`rule|indicator|crypto_constant|embedded_payload|packer|ioc`), `title`,
  `name`, `description`, `severity`, `mitre`, `mitre_names`, `rva`, `offset`, `evidence[]`,
  `explain_key`, `verdict`. Update `web/src/api/types.ts` (`FindingRow`) + `FindingsView.tsx`
  (React key must be `id`; show `source_id`).
- Add to `web/src/api/client.ts`: `triage(sha)`, `jobStatus(sha)`, `strings(sha, category, query,
  offset, limit)` (NOTE: name clash with existing `strings(lang)` UI-text call — call the new one
  `getStrings`), `iocs`, `exportIocs(sha, fmt)`, `xrefsTo(sha, rva)`, `annotate(sha, kind, value,
  address, target)`, `deleteAnnotation`, `listAnnotations`, `setVerdict(sha, factId, verdict|null)`,
  `listPayloads`, `openPayload(sha, payloadSha)`, `exportPayload(sha, payloadSha, path)`.
  Bridge calls pass params positionally in Python signature order.
- Explanations: `t(explain_key + ".explain")`, and `t("fact." + kind + ".next")`.
- Add `compact: bool` to `get_settings/set_settings` (Python + test) for the Compact toggle.
- Every new UI string -> both `en.py` and `az.py` (`test_web_strings.py` enforces).
- Verify visually in the desktop window (`.venv/Scripts/python -m octov.app.desktop <file>`,
  screenshot via PrintWindow) in both languages and both display modes; rebuild web first.

Rulings made so far (also in the ledger; tasks 8-12 rulings are only in the ledger): indicator evidence uses real locations (IAT slot
RVAs for API indicators, section VA/raw offset, entry RVA); header-level facts and
import-only rule matches anchor at offset 0/rva 0; extra crypto signatures (AES inverse
S-box, SHA-1 init, TEA delta); image resources (PNG/JPEG/GIF/BMP/RIFF/ICO) are never
reported as high-entropy payloads; helpers `payload_facts` and `packer_fact` added.

### Other open work
- PR #3 (M2, base `main`) — CI green, Auto-fix ON.
- PR #4 (web UI, base `feat/m2-static-engine`) — Auto-fix ON. Merge order: #3 → retarget
  #4 to `main` → merge → rebase `feat/assisted-triage` onto `main`, then open its PR.
- After Phase 1: Phase 2 (capa, FLOSS), Phase 3 (Ghidra decompiler), Phase 4 (symbol tree,
  call graph, memory map, search), Phase 5 (FLIRT-like, PDB, binary diff); M3 dynamic; M5 AI.

Known limitation: tail jumps are followed as intra-function edges (CRT entry functions absorb
their tail-called body).

### Extra environment notes learned in chat 1
- Bash heredocs that contain `\0`/`\x00` escapes can write literal NUL bytes into files
  (Python then refuses to import them). For non-trivial edits write a small Python script with
  the Write tool to a temp file and run it with `.venv/Scripts/python <script>`.
- Desktop window screenshot: `PrintWindow(hwnd, hdc, 2)` via PowerShell Add-Type; the window
  handle is `(Get-Process python | ? MainWindowTitle -eq "OctoV").MainWindowHandle`.
- Rebuild the web UI after any `web/` change before testing the desktop app.
