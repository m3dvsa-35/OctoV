import { describe, expect, it } from "vitest";
import type { AiReport } from "../api/types";
import { aiError, aiNotes, chips, overlayEdges } from "./ai";

const REPORT: AiReport = {
  summary: "Injects code.",
  assessment: "malicious",
  confidence: "high",
  story: [
    { text: "Prepares the target.", functions: [0x1000], findings: ["indicator:x:0x10"] },
    { text: "Exits.", functions: [], findings: [] },
  ],
  points: [
    {
      title: "Process injection",
      why: "Two APIs.",
      severity: "high",
      findings: ["indicator:x:0x10"],
      functions: [0x1000, 0x1100],
      iocs: ["http://x.example/a"],
    },
  ],
  links: [
    { from: 0x1000, to: 0x1100, why: "passes the buffer" },
    { from: 0x1100, to: 0x2000, why: "starts the thread" },
  ],
  dropped: 0,
  model: "m",
  host: "127.0.0.1",
  local: true,
  created: 0,
  bundle_hash: "0".repeat(16),
  omitted: {},
};

describe("aiNotes", () => {
  it("collects what the AI said about each function, without repeats", () => {
    const notes = aiNotes(REPORT);
    expect(notes.get(0x1000)).toEqual(["Prepares the target.", "Process injection", "passes the buffer"]);
    expect(notes.get(0x1100)).toEqual(["Process injection", "passes the buffer", "starts the thread"]);
    expect(notes.get(0x2000)).toEqual(["starts the thread"]);
    expect(notes.has(0x9999)).toBe(false);
    expect(aiNotes(null).size).toBe(0);
  });
});

describe("overlayEdges", () => {
  it("keeps links whose both ends are shown", () => {
    const edges = overlayEdges(REPORT, new Set([0x1000, 0x1100]), new Set());
    expect(edges).toEqual([{ id: "ai-4096-4352", src: 0x1000, dst: 0x1100, why: "passes the buffer", duplicate: false }]);
  });

  it("flags a link that is already a call edge instead of drawing it twice", () => {
    const edges = overlayEdges(REPORT, new Set([0x1000, 0x1100, 0x2000]), new Set(["4096-4352"]));
    expect(edges.map((e) => [e.id, e.duplicate])).toEqual([
      ["ai-4096-4352", true],
      ["ai-4352-8192", false],
    ]);
    expect(overlayEdges(null, new Set([1]), new Set())).toEqual([]);
  });
});

describe("chips", () => {
  const names = new Map([[0x1000, "inject_main"]]);

  it("turns citations into chips: functions, findings, IOCs", () => {
    expect(chips(REPORT.points[0]!, names)).toEqual([
      { kind: "function", label: "inject_main", target: 0x1000 },
      { kind: "function", label: "sub_1100", target: 0x1100 },
      { kind: "finding", label: "indicator:x:0x10", target: "indicator:x:0x10" },
      { kind: "ioc", label: "http://x.example/a", target: "http://x.example/a" },
    ]);
    expect(chips(REPORT.story[1]!, names)).toEqual([]);
  });
});

describe("aiError", () => {
  const t = (key: string) => ({ "ai.error.auth": "The key was rejected", "analysis.not_ready": "Still analysing" })[key] ?? key;

  it("translates error keys and keeps other messages", () => {
    expect(aiError("ai.auth", t)).toBe("The key was rejected");
    expect(aiError("analysis.not_ready", t)).toBe("Still analysing");
    expect(aiError("ai.something_new", t)).toBe("ai.error.something_new");
    expect(aiError("unknown sample abc", t)).toBe("unknown sample abc");
  });
});
