# OctoV — Phase 4: relations, search, symbols, memory map (design)

Parent spec: `2026-11-08-assisted-analysis-design.md` (§6 Phase 4 "Navigation depth").
Phases 1-3 are merged into `main`. Status: builder's design. The owner handed the decisions to
the builder on 2026-11-10 ("think like an analyst and do what is needed"), so every choice
below is the builder's call, open to correction in the PR.

## 1. Intent

OctoV explains single functions well (disassembly, graph, pseudo-C) but not how the parts of a
sample hang together. An analyst looking at a suspicious function asks three things next:

1. **How does execution get here?** (who calls it, and the chain from the entry point)
2. **What does it lead to?** (what it calls, and which sensitive APIs sit behind those calls)
3. **Where else is this?** (the same bytes, constant, instruction or API elsewhere in the file)

Phase 4 answers these. It is also the base for the later AI overlay, which must show "what is
suspicious and how the parts are linked" on top of the same relations data.

## 2. Goals, non-goals, anti-goals

**Goals**
1. **Relations tab**: the neighbourhood of the current function as a graph: callers on the
   left, callees on the right (depth 1-3 each way), each node showing its name, suspicion score
   and the API families it uses; the shortest call path from the entry point or an export to
   the current function is emphasised. Clicking a node re-centres; double-click opens its code.
2. **Search tab**: byte patterns with `??` wildcards, instruction text, immediate values;
   results list with function names; click navigates.
3. **Symbols** in the sidebar: imports grouped by DLL with the number of referencing places
   (click -> the existing xref popover), exports (click -> navigate).
4. **Memory map** in the Overview tab: headers / sections / overlay as a proportional strip
   with name, permissions and entropy as text; clicking a section opens it in the hex view.
5. Works for raw (shellcode) samples wherever the data exists (relations, search).

**Non-goals**
- Windows API prototypes for call-site argument hints (parent spec): Ghidra's pseudo-C already
  shows typed arguments since Phase 3.
- A whole-program call graph picture (unreadable beyond a few dozen nodes); only neighbourhoods.
- Regular-expression search and string search (the Strings tab already filters strings).
- Labels in the symbol list (OctoV has no label model yet), indirect-call resolution.

**Anti-goals**
- A graph that needs colour to be understood, or that freezes on large files.
- Any new fact or score: Phase 4 only shows relations of existing analysis results (the
  System32 baselines stay untouched).

## 3. Constraints

- All data comes from the existing slow lane: `Function.calls`, `XrefIndex`, `ranking`,
  `naming.API_FAMILIES`, `scoring.SUSPICIOUS_FAMILIES`. No new analyzer state chip; the call
  graph is built lazily on the first request and cached on the sample.
- UI rules from CLAUDE.md: virtualised lists, ELK layout in its worker, shallow-stable store
  selectors, never colour alone, every string in `en.py` and `az.py`.
- `WorkbenchApi` stays the only UI<->core contract; parameters keep the Python signature order.

## 4. Approaches considered

- **A. Neighbourhood graph centred on the current function (chosen).** Bounded size, always
  readable, answers questions 1 and 2 directly, and gives the AI overlay a small surface to
  draw on. Costs: no bird's-eye view.
- **B. Whole-program call graph with filtering.** Familiar from other tools, but twinui.dll
  has 18 551 functions: layout time and readability rule it out as the default view.
- **C. Caller/callee tree lists (no graph).** Cheapest, but loses the "how parts are linked"
  picture the owner asked for, and shared callees are duplicated. Kept only as the way hidden
  neighbours are counted ("+12 more").

API usage is shown as chips inside each function node rather than as separate leaf nodes
(an earlier note): 20 functions calling `CreateFile` would otherwise add 20 edges of noise.

## 5. Design

### 5.1 Call graph (`core/analysis/callgraph.py`)

- `CallGraph.build(functions, xrefs)`: `callees[f]` = starts in `f.calls` that are discovered
  functions, plus targets of `jump` xrefs from `f` that are another function's start (tail
  calls); `callers` is the reverse. Self-calls are kept as a flag, not as an edge.
- `neighbourhood(center, callers_depth, callees_depth, max_nodes=60)`: breadth-first each way;
  nodes carry `role` (`center|caller|callee|both`) and `distance`; when `max_nodes` cuts the
  walk, the result is `truncated` and every node reports `hidden_callers` / `hidden_callees`
  (neighbours that exist but are not shown). Edges only between shown nodes.
- `path_to(center, roots)`: shortest caller chain from any root (entry point, exports) to the
  centre, as a list of starts (empty when unreachable or the centre is a root).
- `apis_of(start)`: imported APIs the function references, normalised (no A/W), with family
  and `suspicious` (family in `SUSPICIOUS_FAMILIES`), sorted suspicious first.

### 5.2 Search (`core/analysis/search.py`)

- `parse_pattern("4D 5A ?? 00")`: hex bytes and `??`/`?` wildcards, spaces optional;
  `ValueError` for anything else, for an empty pattern and for an all-wildcard pattern.
- `search_bytes(data, pattern, limit)`: file offsets (compiled to one `re` over bytes).
- `search_text(functions, query, limit)`: case-insensitive substring over
  `mnemonic operands ; comment` of every discovered instruction.
- `search_immediate(functions, value, limit)`: instructions with an operand number equal to
  `value` (hex or decimal token), or whose `target` / `data_ref` equals it.
- Every search stops at `limit` (default 500) and reports `truncated`.

### 5.3 API (`app/api.py`)

- `get_relations(sha, start, callers=2, callees=2)` -> `{center, nodes:[{start, name, role,
  distance, score, apis:[{name, family, suspicious}], is_entry, is_export, recursive,
  hidden_callers, hidden_callees}], edges:[{src, dst}], path:[start...], truncated}`.
  `score` = the function's ranking score (0 when unranked). Depths are clamped to 1..3.
  `ApiError("no function at …")` for an unknown start.
- `search(sha, kind, query, limit=500)` with `kind` in `bytes|text|imm` -> `{items:[{rva,
  offset, function, function_name, text}], truncated}`. Byte hits outside any mapped section
  have `rva: null`. Bad input -> `ApiError("search.bad_pattern")` / `search.bad_number`.
- `get_symbols(sha)` -> `{imports:[{dll, functions:[{name, rva, refs}]}], exports:[{name, rva,
  function}]}` (`rva` = IAT slot, `refs` = xrefs to it; empty lists for raw samples).
- `get_memory_map(sha)` -> `{size, regions:[{name, kind: headers|section|overlay|raw, rva,
  vsize, offset, size, perm, entropy}]}` in file order.

### 5.4 Web UI

- **Relations tab** (`relations`, main and side panels, next to Graph): xyflow + the ELK worker
  (layered, direction RIGHT). Node: name, `score` as a number with the word (when > 0), entry /
  export badge, API family chips (suspicious families first, marked with an icon and bold
  text; at most 4 chips then "+n"), "+n callers / +n callees" hints for hidden neighbours.
  Edges on the entry path are thick and labelled "path"; others thin. Header: function name,
  depth switches (callers 1-3, callees 1-3), a truncation note. Click = re-centre (navigate
  to the start, staying on the tab); double-click = open Disassembly.
- **Search tab** (`search`, main and side): kind switch (Bytes / Text / Value), input, Enter
  runs; virtualised results `address · function · text`; count with "first 500" when truncated;
  a one-line syntax hint per kind.
- **Sidebar "Symbols" tab**: filter box; virtualised rows: DLL headers, imports with a `refs`
  count (click -> xref popover for the IAT slot), an Exports group (click -> navigate).
- **Overview: memory map** strip above the sections table; segment width ∝ file size (min
  width so small regions stay visible), text label = name + permissions; entropy in the
  tooltip and in the legend row; click a section -> hex view at its start.
- Triage "Most suspicious functions": a "Relations" jump next to "Pseudo-C".

### 5.5 Speed budget

- `get_relations` ≤ 50 ms after the first call on a 20 000-function sample (graph build once,
  ≤ 1 s); byte search ≤ 1 s on a 20 MB file; text/value search ≤ 3 s on 20 000 functions.

## 6. Testing

- Unit: call graph on small hand-made graphs (depth, truncation, hidden counts, path, tail
  calls, recursion), search parsers and searches on synthetic functions/bytes, API results on
  the synthetic injector sample, raw sample behaviour.
- UI: vitest for the relations layout helper and search-input helpers; browser check EN/AZ.
- Baseline: unaffected (no new facts); a speed check on a large System32 DLL recorded in
  CLAUDE.md.

## 7. Left to the builder

Node sizes and exact chip wording, ELK options, result row layout, hint texts, the minimum
segment width of the memory map.
