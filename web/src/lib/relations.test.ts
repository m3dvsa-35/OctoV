import { describe, expect, it } from "vitest";
import type { RelationNode, Relations } from "../api/types";
import { familyChips, nodeSize, pathLength, scoreWord, toRelationsGraph } from "./relations";

function node(start: number, extra: Partial<RelationNode> = {}): RelationNode {
  return {
    start,
    name: `sub_${start.toString(16)}`,
    role: "callee",
    distance: 1,
    score: 0,
    apis: [],
    is_entry: false,
    is_export: false,
    recursive: false,
    hidden_callers: 0,
    hidden_callees: 0,
    ...extra,
  };
}

const REL: Relations = {
  center: 2,
  nodes: [node(1, { role: "caller", is_entry: true }), node(2, { role: "center", distance: 0 }), node(3), node(4)],
  edges: [
    { src: 1, dst: 2 },
    { src: 2, dst: 3 },
    { src: 2, dst: 4 },
    { src: 1, dst: 4 },
  ],
  path: [1, 2],
  truncated: false,
};

describe("toRelationsGraph", () => {
  it("lays every function out left to right with unique edges", () => {
    const g = toRelationsGraph(REL);
    expect(g.layoutOptions["elk.direction"]).toBe("RIGHT");
    expect(g.children.map((c) => c.id)).toEqual(["1", "2", "3", "4"]);
    expect(new Set(g.edges.map((e) => e.id)).size).toBe(4);
    expect(g.children.every((c) => c.width > 0 && c.height > 0)).toBe(true);
  });

  it("marks only the edges of the entry path", () => {
    const g = toRelationsGraph({ ...REL, center: 3, path: [1, 2, 3] });
    expect(g.edges.filter((e) => e.onPath).map((e) => e.id)).toEqual(["1-2", "2-3"]);
    expect(toRelationsGraph({ ...REL, path: [] }).edges.some((e) => e.onPath)).toBe(false);
  });

  it("drops edges whose ends are not shown", () => {
    const g = toRelationsGraph({ ...REL, edges: [...REL.edges, { src: 9, dst: 2 }] });
    expect(g.edges.map((e) => e.id)).not.toContain("9-2");
  });
});

describe("familyChips", () => {
  const apis = [
    { name: "CreateRemoteThread", family: "thread_inject", suspicious: true },
    { name: "WriteProcessMemory", family: "thread_inject", suspicious: true },
    { name: "CreateFile", family: "file_io", suspicious: false },
    { name: "GetTickCount", family: null, suspicious: false },
    { name: "GetLastError", family: null, suspicious: false },
  ];

  it("groups by family, suspicious first, uncategorised APIs last", () => {
    expect(familyChips(apis).shown).toEqual([
      { family: "thread_inject", count: 2, suspicious: true, names: ["CreateRemoteThread", "WriteProcessMemory"] },
      { family: "file_io", count: 1, suspicious: false, names: ["CreateFile"] },
      { family: null, count: 2, suspicious: false, names: ["GetTickCount", "GetLastError"] },
    ]);
  });

  it("shows at most `max` chips and counts the rest", () => {
    const chips = familyChips(apis, 1);
    expect(chips.shown.map((c) => c.family)).toEqual(["thread_inject"]);
    expect(chips.more).toBe(2);
    expect(familyChips([]).shown).toEqual([]);
  });
});

describe("scoreWord", () => {
  it.each([
    [0, null],
    [1, "low"],
    [11, "low"],
    [12, "medium"],
    [29, "medium"],
    [30, "high"],
    [90, "high"],
  ])("%i -> %s", (score, word) => {
    expect(scoreWord(score)).toBe(word);
  });
});

describe("nodeSize", () => {
  it("grows with the rows a node shows", () => {
    const plain = nodeSize(node(1));
    const scored = nodeSize(node(1, { score: 30 }));
    const chips = nodeSize(node(1, { score: 30, apis: [{ name: "send", family: "net_socket", suspicious: true }] }));
    const hints = nodeSize(node(1, { score: 30, hidden_callers: 4 }));
    expect(scored.height).toBeGreaterThan(plain.height);
    expect(chips.height).toBeGreaterThan(scored.height);
    expect(hints.height).toBeGreaterThan(scored.height);
    expect(plain.width).toBe(chips.width);
  });
});

describe("pathLength", () => {
  it("counts the calls between the entry point and the function", () => {
    expect(pathLength([1, 2, 3])).toBe(2);
    expect(pathLength([])).toBe(0);
  });
});
