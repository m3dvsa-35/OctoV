import { describe, expect, it } from "vitest";
import {
  annotationIndex,
  bandOf,
  filterStrings,
  formatScoreBand,
  groupByNamespace,
  groupContributions,
  jobLabel,
  libraryCount,
  offsetLabel,
  positiveContributions,
  verdictCounts,
  visibleFunctions,
} from "./triage";

describe("bandOf", () => {
  it.each([
    [0, "low"],
    [29, "low"],
    [30, "medium"],
    [59, "medium"],
    [60, "high"],
    [100, "high"],
  ])("%d -> %s", (score, band) => {
    expect(bandOf(score)).toBe(band);
  });
});

describe("positiveContributions", () => {
  it("drops zero-point rows and keeps order", () => {
    const rows = [
      { fact_id: "a", points: 30, title: "A", severity: "high" as const },
      { fact_id: "b", points: 0, title: "B", severity: "high" as const },
      { fact_id: "c", points: 4, title: "C", severity: "low" as const },
    ];
    expect(positiveContributions(rows).map((r) => r.fact_id)).toEqual(["a", "c"]);
  });
});

describe("verdictCounts", () => {
  it("counts reviewed facts", () => {
    expect(verdictCounts([{ verdict: "false_positive" }, { verdict: null }, { verdict: "confirmed" }])).toEqual({
      reviewed: 2,
      total: 3,
    });
  });
});

describe("formatScoreBand", () => {
  it("clamps and rounds the score and derives the band", () => {
    expect(formatScoreBand(42.6)).toEqual({ score: 43, band: "medium", percent: 43 });
    expect(formatScoreBand(-5)).toEqual({ score: 0, band: "low", percent: 0 });
    expect(formatScoreBand(140)).toEqual({ score: 100, band: "high", percent: 100 });
  });
});

describe("groupContributions", () => {
  it("groups positive rows by severity (high first) with point totals", () => {
    const rows = [
      { fact_id: "a", points: 4, title: "A", severity: "low" as const },
      { fact_id: "b", points: 30, title: "B", severity: "high" as const },
      { fact_id: "c", points: 0, title: "C", severity: "high" as const },
      { fact_id: "d", points: 12, title: "D", severity: "high" as const },
    ];
    expect(groupContributions(rows)).toEqual([
      { severity: "high", points: 42, rows: [rows[1], rows[3]] },
      { severity: "low", points: 4, rows: [rows[0]] },
    ]);
  });
});

describe("filterStrings", () => {
  const items = [
    { value: "http://a.example/x", category: "url" },
    { value: "kernel32.dll", category: null },
    { value: "HKLM\Software\Run", category: "registry" },
  ];
  it("filters by category and case-insensitive query", () => {
    expect(filterStrings(items, { category: "url" }).map((x) => x.value)).toEqual(["http://a.example/x"]);
    expect(filterStrings(items, { query: "SOFT" }).map((x) => x.value)).toEqual(["HKLM\Software\Run"]);
    expect(filterStrings(items, {})).toHaveLength(3);
    expect(filterStrings(items, { category: "url", query: "kernel" })).toEqual([]);
  });
});

describe("annotationIndex", () => {
  it("indexes comments, bookmarks and names by address; latest wins", () => {
    const idx = annotationIndex([
      { id: 1, kind: "comment", address: 16, target: null, value: "old" },
      { id: 2, kind: "comment", address: 16, target: null, value: "new" },
      { id: 3, kind: "bookmark", address: 32, target: null, value: "" },
      { id: 4, kind: "name", address: 64, target: null, value: "decrypt_cfg" },
      { id: 5, kind: "verdict", address: null, target: "rule:X:0x0", value: "benign" },
    ]);
    expect(idx.comments).toEqual({ 16: { id: 2, value: "new" } });
    expect(idx.bookmarks).toEqual({ 32: 3 });
    expect(idx.names).toEqual({ 64: "decrypt_cfg" });
  });
});

describe("groupByNamespace", () => {
  const row = (source_id: string, tags: string[]) => ({ source_id, tags });
  it("groups capa facts by top-level namespace, biggest first, other last", () => {
    const groups = groupByNamespace([
      row("a", ["C0038", "host-interaction/thread/create"]),
      row("b", ["persistence/registry/run"]),
      row("c", ["host-interaction/file-system/write"]),
      row("d", []),
    ]);
    expect(groups.map((g) => [g.namespace, g.rows.map((r) => r.source_id)])).toEqual([
      ["host-interaction", ["a", "c"]],
      ["persistence", ["b"]],
      ["other", ["d"]],
    ]);
  });
});

describe("jobLabel", () => {
  const t = (key: string) => ({ "ext.cached": "cached", "ext.queued": "queued" })[key] ?? key;
  it.each([
    [{ state: "running", elapsed_s: 42.3, cached: false }, "running · 42 s"],
    [{ state: "done", elapsed_s: 3.1, cached: true }, "done · cached"],
    [{ state: "done", elapsed_s: 12, cached: false }, "done · 12 s"],
    [{ state: "queued", elapsed_s: null, cached: false }, "queued"],
    [{ state: "failed", elapsed_s: null, cached: false }, "failed"],
  ])("%o -> %s", (job, label) => {
    expect(jobLabel(job, (k) => (k.startsWith("triage.job.") ? k.slice(11) : t(k)))).toBe(label);
  });
});

describe("offsetLabel", () => {
  it("shows a dash for strings with no file offset (recovered at run time)", () => {
    expect(offsetLabel(-1)).toBe("—");
    expect(offsetLabel(0x40)).toBe("000040");
  });
});

describe("visibleFunctions", () => {
  const fn = (start: number, name: string, library = false) => ({ start, name, library });
  const rows = [fn(0x1000, "sub_1000"), fn(0x2000, "memcpy", true), fn(0x3000, "net_http_3000")];

  it("returns everything without a query or filter", () => {
    expect(visibleFunctions(rows, "", false)).toBe(rows);
  });
  it("filters by name or hex address, case-insensitively", () => {
    expect(visibleFunctions(rows, " MEM ", false).map((f) => f.start)).toEqual([0x2000]);
    expect(visibleFunctions(rows, "3000", false).map((f) => f.start)).toEqual([0x3000]);
  });
  it("hides library functions on request", () => {
    expect(visibleFunctions(rows, "", true).map((f) => f.start)).toEqual([0x1000, 0x3000]);
    expect(visibleFunctions(rows, "mem", true)).toEqual([]);
  });
  it("counts library functions", () => {
    expect(libraryCount(rows)).toBe(1);
    expect(libraryCount([])).toBe(0);
  });
});
