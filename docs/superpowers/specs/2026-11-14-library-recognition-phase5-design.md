# OctoV — Phase 5a: library-function recognition (design)

Parent spec: `2026-11-08-assisted-analysis-design.md` (§6 Phase 5 "Knowledge & comparison").
Status: builder's design. On 2026-11-14 the owner chose "Phase 5, starting with library
recognition"; as in earlier phases the choices below are the builder's calls, open to
correction in the PR. Phase 5 is three independent projects; this document covers only the
first. PDB symbols and binary diff get their own designs later.

## 1. Intent

A statically linked program is mostly code nobody needs to read: the C runtime, the C++
standard library, zlib, OpenSSL. Today OctoV shows all of it as `sub_401000`, next to the few
functions the author actually wrote, and a beginner cannot tell them apart. Recognising known
library functions gives them their real names (`memcpy`, `_initptd`, `inflate`) and lets the
analyst skip them, so attention goes to the sample's own code.

## 2. Goals, non-goals, anti-goals

**Goals**
1. After the functions of a PE are discovered, known library functions get their real name
   and a "library" mark, without the analyst doing anything.
2. The sidebar function list shows the mark as text (`lib`) and can hide library functions.
3. The "where to look first" ranking skips library functions, unless a medium or high
   severity fact points into one.
4. Triage says how much of the sample is known library code ("166 of 243 functions").
5. The names appear everywhere a function name appears (disassembly, graph, relations, search,
   xrefs, AI evidence), below the analyst's own names and export names.

**Non-goals**
- Demangling C++ names (`??2@YAPEAX_K@Z` stays as it is), own signature creation, signatures
  for Delphi / Go / Rust / MinGW, raw shellcode blobs, carved in-memory payloads.
- Passing library names to Ghidra (its pseudo-C keeps its own Function ID names).
- PDB symbols and binary diff (later Phase 5 designs).

**Anti-goals**
- A wrong library name on the sample's own code. A missed library function costs a little
  reading time; a wrong name hides code. Precision wins over coverage everywhere below.
- Any new fact or any change to the risk score: the System32 baselines stay untouched.
- Hundreds of megabytes held by the application process.

## 3. What was measured first (throwaway spike, 2026-11-14)

`python-flirt` 0.10.2 (Rust matcher, already installed as a capa dependency) with the three
FLARE signature files that `octov ext setup capa` already installs and pins by SHA-256
(`~/.octov/capa-sigs/v10.0.0`, 711 752 signatures):

- Load + compile: 2.75 s. Matching every function of a file: 0.01-0.08 s.
- Memory: +181 MB for the MSVC runtime file, +617 MB for all three.
- Hit rate on statically linked MSVC programs (pip's `t32.exe` / `t64.exe`): 166 of 243 and
  214 of 277 functions get exactly one name. On dynamically linked System32 programs only the
  small static startup part matches (notepad 30, tar 21, curl 62).
- Wrong names seen: one MFC name each in notepad.exe and curl.exe
  (`?OnInitDialog@CMFCKeyMapDialog@@MEAAHXZ` on a 1 216-byte function): a lone match from a
  signature file whose library is not in the program. Functions under 16 bytes almost never
  get a unique name (2 of 105).

## 4. Approaches considered

- **A. FLIRT signatures through `python-flirt`, in a short-lived child process (chosen).**
  Real names for MSVC runtime, ATL/MFC and common C libraries; the signature files are already
  pinned and installed; matching is exact byte patterns with CRC, so it is fast and explainable.
  The 617 MB live only for the few seconds the child runs; the result is cached per sample.
  Costs: one process start (~3-4 s) per new sample; coverage is what the FLARE files cover.
- **B. The same matcher inside the application process.** No process start, but 617 MB stay
  resident for the lifetime of the window (181 MB with the runtime file only). Rejected: the
  owner's priority is "fast and trouble-free", and a desktop tool that sits at 0.7 GB is not.
- **C. Ghidra's Function ID.** Already installed for the decompiler, but its analysis takes
  25 s to 6 min per file, is optional, and its names would arrive long after the first view.
  Rejected as the primary source; nothing prevents using it later as a second one.
- **D. Own signature database.** There is no redistributable source of library object files to
  build it from, and it would repeat years of FLARE's work. Rejected.

## 5. Design

### 5.1 Pieces

| Piece | Where | What it does |
|-------|-------|--------------|
| Worker | `octov/ext/library_worker.py` | Child process, the only place `flirt` is imported. Reads the sample, the signature folder and a list of function starts; prints candidate names as JSON. |
| Adapter | `octov/ext/library.py` | Status probe (module + signature folder), command line, parsing of the worker's document. |
| Policy | `octov/core/analysis/library.py` | Pure function: candidates + function sizes -> accepted `LibraryMatch`es. No I/O. |
| Apply | `octov/ext/apply.py` `apply_library` | Stores the result on the sample and re-runs naming and ranking. |
| API | `octov/app/api.py` | Scheduling after the slow lane, cache, job state `library`, names, `library` flag, triage count. |
| UI | `web/src` Sidebar, Triage, engine chips | `lib` tag, "hide library" toggle, the count line. |

`library` is a third engine next to `floss` and `capa`: same isolation (`runner.run_engine`,
Job Object, memory limit, timeout, cancel), same one-at-a-time queue, same cache
(`~/.octov/cache/<sha>/library-<worker version>-<signature set>.json.gz`), same job states
(`queued | running | done | failed | unavailable | idle`), same auto-run setting
(`extensions_auto_run.library`, default on) and `run_extension(sha, "library", force)`.

### 5.2 Worker

`python -m octov.ext.library_worker <sample> <signature dir> <starts file>`

- The starts file is a JSON list of function RVAs written by the parent to a temp file (the
  functions are already discovered; discovering them again would cost up to 50 s on big files).
- Signature files: every `*.sig` (and `*.pat`, which lets tests build tiny signature sets) in
  the folder, each compiled into its own matcher so every candidate knows its signature file.
- For each start: bytes from the function start to the end of its section, at most 0x8000,
  matched against every file. A candidate name is a name at offset 0 of kind `public` or
  `local` that is not `?`.
- Output: `{"engine": "library", "version": 1, "sets": [{"file", "signatures"}],
  "candidates": [{"rva", "set", "names": [first 4, sorted], "count"}]}`. The worker reports
  raw candidates only; what is accepted is decided by the policy in the parent, so the cache
  stays valid when the policy is tuned.

### 5.3 Policy (precision first)

A candidate becomes a library match only if all of these hold:

1. **One name.** Exactly one distinct name across all signature files for that function.
2. **Not tiny.** The function is at least `MIN_SIZE = 16` bytes.
3. **The library is really there.** Its signature file has at least `MIN_PER_SET = 5` matches
   that passed rules 1-2 in this sample. A lone look-alike from a library the program does not
   contain (the MFC case above) is dropped.

Result: `LibraryMatch(start, name, source)` where `source` is the signature file name; stored
as `ctx.results["library"]: dict[int, LibraryMatch]`.

### 5.4 Effects

- **Names.** Order everywhere: analyst name > export name > library name > suggested name
  (capa / API family) > `sub_…`. `list_functions` rows get `library: bool` (true only when the
  library name is the one shown); `suggested` stays false for them.
- **Ranking.** `rank_functions` gets the set of library starts and leaves those functions out,
  except when a fact of severity medium or high has evidence in them: a rare evasion artifact
  is never hidden because of a name.
- **Triage.** `get_triage` adds `library: {"functions": n, "total": m}`; the Triage tab shows
  one line when `n > 0`. No fact, no score contribution.
- **AI evidence.** Function names in the bundle follow the same naming order, nothing else
  changes. (The bundle hash changes when names change; reports are then shown as stale, as
  with any rename.)
- **Concurrency.** capa and library both re-run naming and ranking when they finish; applying
  an engine result takes a per-sample lock so the two cannot interleave.

### 5.5 Availability

- `flirt` module: `python-flirt>=0.10,<1` becomes a core dependency (a ~300 KB wheel that is
  already in the lock file through capa). Missing module -> `unavailable`,
  `ext.reason.not_installed`.
- Signatures: the newest version folder under `~/.octov/capa-sigs` that holds a `*.sig` /
  `*.pat` file. None -> `unavailable`, `ext.reason.no_signatures`, with the setup command
  `octov ext setup library` (new: installs only the pinned signature files through the
  existing `install_sigs`; `octov ext setup capa` keeps installing them too). Nothing is
  downloaded without that explicit command.
- Raw blobs -> `ext.reason.pe_only`; carved payloads and files that changed on disk ->
  the existing `ext.reason.in_memory` / "file changed on disk" behaviour.
- Limits (`config.extensions["library"]`): timeout 120 s, memory 2048 MB, size 64 MB.
- The triage CLI and `scripts/baseline_sweep.py` do not run it (no facts, no score).

### 5.6 UI

- Sidebar functions: library rows are dimmed and carry the text tag `lib`
  (hover: "Known library function (signature file …)"); a toggle "Hide library (N)" above the
  list, off by default, kept in the store for the session.
- Engine chips / Extensions dialog: `library` appears with the other engines (state, rerun).
- Triage: "Known library code: N of M functions; they are left out of the ranking."
- All new strings in `en.py` and `az.py`.

## 6. Testing

- Policy: unit tests for each rule (ambiguous, tiny, lone match per set, accepted).
- Worker: tests build a synthetic PE (`tests/samples/builder.py`) and a `.pat` signature file
  from the bytes of its functions, then run the matching function in-process and once as a
  real child process. No network, no FLARE files needed in CI.
- API: fake worker output through the existing `engines` fixture style; names order, `library`
  flag, ranking exclusion and its medium/high exception, triage count, cache hit,
  unavailable reasons, risk score identical with and without library results.
- Real signatures (skipped when not installed): pip's `t64.exe` gets >= 150 library names;
  notepad.exe gets no name from the ATL/MFC file.
- UI: vitest for the list filter helper; visual check in the browser pane in EN and AZ.

## 7. Left to the builder

Exact wording of strings, the look of the `lib` tag, where the temp starts file lives, the
timing table recorded in CLAUDE.md after the build.
