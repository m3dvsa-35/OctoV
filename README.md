# OctoV

**Windows Binary Analysis Workbench for Defensive Security Operations** —
detection engineering, incident response, threat hunting, security research and education.

OctoV helps defenders analyse suspicious Windows binaries **they are authorised to examine**,
recognise adversary techniques (position-independent code, memory manipulation, sensor evasion)
and turn findings into defender artifacts (YARA, Sigma, STIX 2.1, IOCs).

> **Defensive only.** OctoV has no offensive capabilities. All analysis runs locally — samples are
> never uploaded anywhere. The optional AI assistant receives only extracted evidence (hashes,
> indicators, offsets), never the binary itself.

## Status

| Milestone | Scope | State |
|-----------|-------|-------|
| **M1** | Skeleton, PE parser + packing indicators, `.octov` sessions, GUI shell, i18n (EN/AZ), CLI `analyze`, CI | ✅ |
| **M2** | Static rule engine (evasion/PIC catalogs), Capstone disassembly, CFG graph, hex, MITRE table, YARA/Sigma export | ✅ |
| **Triage P1** | Assisted triage: fact pipeline, risk score, strings/IOCs, xrefs, crypto constants, payload carving, packer verdict, function ranking, verdicts + annotations, `triage` CLI | ✅ |
| **Triage P2** | Optional engines: capa (capabilities per function, ATT&CK/MBC) and FLOSS (stack/tight/decoded strings, hidden IOCs), isolated, cached, offline | ✅ |
| **Decompiler P3** | Optional Ghidra decompiler: Pseudo-C view per function synced with disassembly/graph, marked lines, API explanations (EN/AZ), isolated worker, cached | ✅ |
| **Navigation P4** | Relations tab (callers / callees neighbourhood, scores, API families, path from the entry point), Search (bytes with wildcards, instruction text, constants), Symbols (imports by DLL with references, exports), file layout map | ✅ |
| M3 | Dynamic analysis: Frida 16.x agent, ETW, Job Object + AppContainer sandbox, VAD/memory forensics, network IOCs | planned |
| M4 | MIL (SSA IL) decompiler MVP → pseudo-C, synced asm/pseudo/graph views | planned |
| **M5 (first slice)** | AI analyst: one confirmed request with a previewed evidence bundle, cited and validated report, overlay on the Relations graph (OpenRouter / any OpenAI-compatible endpoint) | ✅ |
| M5 (later) | Follow-up questions, guided workflows | planned |
| M6 | Reports (HTML/PDF), STIX 2.1, MISP, Snort, plugin API, `compare` CLI | planned |

## Requirements

- Windows 10/11 x64 (static analysis also works on Linux/macOS)
- Python 3.11+ (3.12 recommended), [uv](https://docs.astral.sh/uv/)
- No administrator rights needed for static analysis

## Quick start

```bash
uv sync
uv run octov analyze path\to\sample.exe
uv run octov analyze sample.exe --json --session case.octov
uv run octov analyze sample.exe --yara sample.yar --sigma sample.yml
uv run octov analyze shellcode.bin --raw --bits 64 --yara shellcode.yar
uv run octov triage sample.exe        # risk score, capabilities, IOCs (--md / --json)
uv run octov triage sample.exe --iocs iocs.csv
uv run octov-gui                      # desktop window (Edge WebView2)
uv run octov serve                    # same UI in a browser, loopback + token
```

Building the UI (once, and after changes in `web/`) needs no system Node.js:

```bash
uv run python scripts/npm.py install
uv run python scripts/npm.py run build
```

Configuration: copy `config.yaml.example` to `config.yaml`. The AI key is read **only** from the
environment:

```powershell
[Environment]::SetEnvironmentVariable("OCTOV_AI_KEY", "<your-key>", "User")
```

## Static indicators (M1)

| Indicator | Severity | MITRE |
|-----------|----------|-------|
| `high_entropy_section` | medium | T1027.002 |
| `rwx_section` | medium | T1027.002 |
| `packer_section_name` (UPX, VMProtect, Themida, …) | medium | T1027.002 |
| `virtual_size_inflated` | low | T1027.002 |
| `entry_point_not_executable` / `entry_point_outside_sections` | high | T1027 |
| `no_imports`, `dynamic_api_resolution` | medium | T1027.007, T1106 |
| `process_injection_apis` | medium (capability) | T1055 |
| `anti_debug_apis` | low | T1622 |
| `overlay_present` | low | — |
| `suspicious_timestamp` | low | T1070.006 |

Every indicator carries structured `evidence` (section, offsets, API names) so later AI reports
can cite it precisely.

## Technique rules (M2)

`rules/evasion_patterns.yaml` (24 rules) and `rules/pic_patterns.yaml` (6 rules) describe
observable artifacts of adversary techniques: byte patterns with nibble wildcards,
ASCII/UTF-16 strings, imports, exports and section names, combined with `any`/`all`/N
conditions and optional `unless` suppressions. Severity guide: **high** = rare evasion
artifact, **medium** = capability via dual-use APIs, **low/info** = weak signal.
Baseline: 0 high-severity hits across the 4370 binaries of a Windows 11 System32.

Findings carry file offset + RVA evidence and feed the generated YARA (compiled and
verified against the sample) and Sigma (pySigma-valid) rules.

## Assisted triage

Opening a sample runs an analyzer pipeline automatically. Fast analyzers (PE indicators, rules,
strings, IOCs, crypto constants, embedded payloads, packer verdict) finish before the UI shows
the sample; slow ones (function discovery, cross-references, suggested names, function
ranking) continue in the background and the report refreshes when they finish.

- **Risk score 0-100** (low / medium / high) with every contributing finding and its points.
- **Explained facts**: each finding has an EN/AZ explanation and a suggested next step, plus
  structured evidence (offset, RVA, API, section). *Compact* mode hides the explanations.
- **Analyst verdicts**: confirm, false positive or benign. False positives and benign facts
  stop counting towards the score; verdicts, names, comments and bookmarks are stored in a
  per-sample workspace (`~/.octov/workspaces/<sha256>.octov`) or the open session.
- **Strings** with IOC categories (URL, IP, domain, registry, mutex, wallet...), search and
  cross-references to the code that uses them; IOCs export as CSV/JSON.
- **Embedded payloads** (PE in overlay/resources, high-entropy blobs) open as a new sample or
  export as an AES-encrypted ZIP (password `infected`); they are never written as plain files.
- **Function ranking** with API-based suggested names (`thread_inject_1000`); rename with `n`,
  comment with `;`, bookmark with `b`, cross-references with `x` or right-click.

## Optional engines: capa and FLOSS

Two open-source engines from Mandiant add depth when installed; OctoV works without them.

| Engine | Adds |
|--------|------|
| [capa](https://github.com/mandiant/capa) | Names what each function does ("inject thread", "encrypt data using AES") with ATT&CK and MBC references; feeds the Triage tab, function ranking and suggested names |
| [FLOSS](https://github.com/mandiant/flare-floss) | Recovers strings built on the stack or decoded at run time; hidden URLs, domains, mutexes and commands become a `hidden_ioc` finding |

```bash
python -m uv sync --extra capa --extra floss
uv run octov ext setup capa      # one-time: pinned capa rules + signatures (sha256-checked)
uv run octov ext status
```

`ext setup capa --from-zip rules.zip --sigs-from sigs/` installs from local files on machines
without internet. The workbench itself never downloads anything.

- Engines run as separate processes (below-normal priority, Windows Job Object memory limit,
  timeout), one capa and one FLOSS process at a time, in the background: the first view never
  waits for them. Limits: `extensions.<engine>` in `config.yaml`.
- Results are cached in `~/.octov/cache/` (per sample, engine and rules version), so reopening
  a sample is instant. "Run again" in the Triage tab ignores the cache.
- Most capa matches are informational (a benign DLL matches 20-40 rules); only a short list of
  behaviours that rarely appear in benign software (process injection, persistence, keylogging,
  anti-VM, obfuscation, impact, C2) count towards the risk score.
- Carved payloads are never written to disk to be scanned: engines run on files only.

## Optional decompiler: Ghidra

The **Pseudo-C** tab shows each function as readable C-like code, produced by
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) running as a separate worker process.

```bash
python -m uv sync --extra ghidra
uv run octov ext setup ghidra    # one-time: pinned Ghidra 12.2 (~570 MB, sha256-checked)
uv run octov ext status          # shows the Ghidra version and the JDK that will be used
```

Ghidra needs a **JDK 21 or newer** (for example Eclipse Temurin). OctoV finds it from
`extensions.ghidra.java_home`, `JAVA_HOME`, the usual `C:\Program Files` vendor folders or
`PATH`; an existing Ghidra 12.x can be used with `extensions.ghidra.install_dir` or
`GHIDRA_INSTALL_DIR` (`ext setup ghidra --from-zip` installs from a local zip).

- Opening a PE starts Ghidra's analysis in the background (one analysis at a time, at most
  `max_workers` workers, memory-limited Job Object). The first view never waits for it; the tab
  shows the elapsed time until the code is ready. Raw shellcode blobs are not decompiled.
- Clicking a line jumps to its instructions in the disassembly and graph; the line of the
  current address is highlighted. Your function names and comments appear in the pseudo-C.
- Help for beginners: lines that call sensitive APIs or carry a finding are marked (icon and
  text, never colour alone), hovering a Windows API shows what it does and why malware uses it,
  and "How to read this" explains `param_1`, `local_10`, `DAT_...`, `FUN_...`.
- Measured on Windows 11 System32 files: first analysis 25 s (50 KB) to about 4 min (5 MB)
  and 5-6 min (10-18 MB); afterwards a function decompiles in about 0.3 s, a cached one in
  about 5 ms, and reopening an analysed sample takes 8-13 s.
- The sample is sent to the worker over a pipe and imported from memory, so carved payloads can
  be decompiled without ever being written to disk as an executable.
- Analysed projects are kept in `%LOCALAPPDATA%\OctoV\ghidra-projects` (deleted after
  `project_keep_days` without use) and pseudo-C in `~/.octov/cache/`, so reopening is fast.
  Idle workers stop after `idle_minutes` and restart on demand.

## Relations, search and symbols

- **Relations** tab: the functions around the current one as a graph, callers on the left
  and called functions on the right (1-3 calls deep each way). Every node shows its name, its
  suspicion score in words, and the API families it uses (sensitive ones marked); the shortest
  call path from the entry point or an export is drawn thick and labelled. Click re-centres,
  double-click opens the code. Hubs are cut to the nearest 60 functions with "+n callers"
  hints, so the picture stays readable on DLLs with 20 000 functions.
- **Search** tab: bytes with `??` wildcards (`4D 5A ?? 00`), instruction text (`xor eax`,
  an API name) or a constant (`0x5A4D`); every hit shows its function and opens in the code
  or hex view.
- **Symbols** in the sidebar: imports grouped by DLL with the number of references (click to
  list the referencing code), and exports.
- **File layout** in the Overview: headers, sections and overlay from first to last byte with
  permissions as text; click a part to see its bytes.

Measured on System32 DLLs with 18 000-20 000 functions: a relations view in about 1 ms (100 ms
the first time), byte search under 0.2 s, text and constant search about 1 s.

## AI analyst (optional)

The **AI analyst** tab asks a language model to explain, in the UI language, what the sample
appears to do and how its parts are linked. It is an opinion on top of OctoV's evidence, never
a replacement for it.

- **You see exactly what is sent, every time.** The tab shows the evidence text verbatim with
  its size and destination; nothing leaves until you press "Send this to <host>", and each
  send asks again. If the evidence changed after you looked (a rename, a verdict), nothing is
  sent and the new text is shown.
- **What is sent:** findings, function names, API calls, strings and the code (pseudo-C if
  already decompiled, otherwise the first instructions) of the most suspicious functions,
  IOCs, section names, your own names and comments; bounded by `ai.max_chars`. **Never the
  file, raw bytes or its folder path.**
- **Only checkable statements are shown.** The model must cite finding ids, function
  addresses and IOCs; each citation is checked against the sample, invented ones are removed
  and counted, and a statement left with no evidence is dropped.
- **On the Relations graph**, functions the AI talked about carry an "AI" mark with its note,
  and AI links are drawn as labelled dashed arcs (switchable).
- **Setup:** set the `OCTOV_AI_KEY` environment variable for the endpoint in `config.yaml`
  (`ai.base_url`, `ai.model`), or point `ai.fallback_base_url` at a local OpenAI-compatible
  server (Ollama, LM Studio): then nothing leaves the machine and no key is needed. Only
  `https://` endpoints are accepted (plain `http://` only on this machine); the key is never
  written to a file, log, error message or the cache. If two endpoints are configured you
  choose the destination; a failed endpoint never falls back to the other one by itself, and
  the key is never sent to a second provider.
- The newest report stays visible when the evidence changes later (new engine results, your
  edits) and is then marked as out of date.

## Workbench UI

A modern desktop UI (React + TypeScript in an Edge WebView2 window): samples and functions
sidebar, overview, virtualised disassembly, control-flow graph with orthogonal routing,
hex view, Triage and Strings tabs, findings with clickable evidence, MITRE ATT&CK tiles, a
Ctrl+K command palette and YARA/Sigma export. Two languages (EN / AZ) and two display modes (Night / Normal).
API calls use pywebview's in-process bridge; the browser mode (`octov serve`) binds to
127.0.0.1 and requires a per-run token.

## Layout

```
src/octov/
  core/static/    PE parser, indicators, rule engine, disassembler, CFG
  core/analysis/  triage pipeline: facts, strings, IOCs, xrefs, crypto, carving, packer, scoring,
                  call graph, search
  ext/            optional engines: runner (Job Object), queue, cache, capa + FLOSS adapters
  ext/ghidra/     decompiler: discovery, setup, worker process, manager, pseudo-C model
  core/dynamic/   Frida/ETW instrumentation (M3)
  core/ai/        AI analyst: evidence bundle, OpenAI-compatible client, cited report
  core/session/   SQLite + msgpack .octov sessions
  core/i18n/      en / az UI strings
  app/            workbench API, desktop shell, dev server
  cli/            headless CLI
  plugins/        plugin API (M6)
rules/            detection catalogs (YAML)
web/              React UI source (built into src/octov/webui/dist)
tests/            unit tests + synthetic benign PE builder
```

## Development

```bash
uv sync
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest
```

Tests never use real malware: `tests/samples/builder.py` synthesises small benign PE files with
exactly the structural traits each test needs.

## License

MIT — see [LICENSE](LICENSE).
