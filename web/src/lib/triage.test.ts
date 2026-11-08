import { describe, expect, it } from "vitest";
import { bandOf, positiveContributions, verdictCounts } from "./triage";

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
