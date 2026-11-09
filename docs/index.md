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
| M3 | Dynamic analysis: Frida 16.x agent, ETW, Job Object + AppContainer sandbox, VAD/memory forensics, network IOCs | planned |
| M4 | MIL (SSA IL) decompiler MVP → pseudo-C, synced asm/pseudo/graph views | planned |
| M5 | AI assistant (OpenRouter / OpenAI-compatible fallback), evidence-cited reports, guided workflows | planned |
| M6 | Reports (HTML/PDF), STIX 2.1, MISP, Snort, plugin API, `triage`/`compare` CLI | planned |

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

## Workbench UI

A modern desktop UI (React + TypeScript in an Edge WebView2 window): samples and functions
sidebar, overview, virtualised disassembly, control-flow graph with orthogonal routing,
hex view, findings with clickable evidence, MITRE ATT&CK tiles, a Ctrl+K command palette and
YARA/Sigma export. Two languages (EN / AZ) and two display modes (Night / Normal).
API calls use pywebview's in-process bridge; the browser mode (`octov serve`) binds to
127.0.0.1 and requires a per-run token.

## Layout

```
src/octov/
  core/static/    PE parser, indicators (decompiler, rule engine: M2/M4)
  core/dynamic/   Frida/ETW instrumentation (M3)
  core/ai/        evidence bundler + AI client (M5)
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
