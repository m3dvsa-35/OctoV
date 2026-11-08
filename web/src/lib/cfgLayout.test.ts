import { describe, expect, it } from "vitest";
import type { FunctionData } from "../api/types";
import { blockLines, toElkGraph } from "./cfgLayout";

const fn: FunctionData = {
  start: 0x1000,
  name: "sub_1000",
  calls: [],
  blocks: [
    {
      start: 0x1000,
      end: 0x1005,
      indirect: false,
      successors: [
        { target: 0x100b, kind: "true" },
        { target: 0x1005, kind: "false" },
        { target: 0x9999, kind: "jump" }, // outside the function: dropped
      ],
      instructions: [
        { address: 0x1000, text: "test rcx, rcx", bytes: "4885c9", mnemonic: "test", operands: "rcx, rcx", target: null, comment: null },
        { address: 0x1003, text: "je 0x100b", bytes: "7406", mnemonic: "je", operands: "0x100b", target: 0x100b, comment: null },
      ],
    },
    { start: 0x1005, end: 0x100b, indirect: false, successors: [], instructions: [] },
    { start: 0x100b, end: 0x100d, indirect: false, successors: [], instructions: [] },
  ],
};

describe("toElkGraph", () => {
  it("creates one node per block and only intra-function edges", () => {
    const g = toElkGraph(fn);
    expect(g.children.map((c) => c.id)).toEqual(["4096", "4101", "4107"]);
    expect(g.edges.map((e) => [e.sources[0], e.targets[0], e.kind])).toEqual([
      ["4096", "4107", "true"],
      ["4096", "4101", "false"],
    ]);
  });

  it("sizes nodes from their longest line", () => {
    const g = toElkGraph(fn);
    const entry = g.children[0];
    expect(entry?.width).toBeGreaterThan(blockLines(fn.blocks[0]!).reduce((m, l) => Math.max(m, l.length), 0) * 7);
    expect(entry?.height).toBeGreaterThan(3 * 16);
  });
});
