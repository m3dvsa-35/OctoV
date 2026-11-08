import { describe, expect, it } from "vitest";
import {
  annotationIndex,
  bandOf,
  filterStrings,
  formatScoreBand,
  groupContributions,
  positiveContributions,
  verdictCounts,
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
