import { describe, expect, it } from "vitest";
import type { MemoryRegion, Symbols } from "../api/types";
import { errorText, mapSegments, symbolRows } from "./search";

const SYMBOLS: Symbols = {
  imports: [
    {
      dll: "advapi32.dll",
      functions: [{ name: "RegSetValueExW", rva: 0x3000, refs: 2 }],
    },
    {
      dll: "kernel32.dll",
      functions: [
        { name: "CreateFileW", rva: 0x3010, refs: 5 },
        { name: "VirtualAlloc", rva: 0x3018, refs: 0 },
      ],
    },
  ],
  exports: [
    { name: "DllMain", rva: 0x1000, function: 0x1000 },
    { name: "Run", rva: 0x1200, function: null },
  ],
};

describe("symbolRows", () => {
  it("lists DLL headers, their imports, then exports", () => {
    expect(symbolRows(SYMBOLS, "").map((r) => (r.kind === "dll" || r.kind === "exports" ? `${r.kind}:${r.count}` : r.name))).toEqual([
      "dll:1",
      "RegSetValueExW",
      "dll:2",
      "CreateFileW",
      "VirtualAlloc",
      "exports:2",
      "DllMain",
      "Run",
    ]);
  });

  it("filters case-insensitively and drops empty groups", () => {
    const rows = symbolRows(SYMBOLS, "  virtual ");
    expect(rows).toEqual([
      { kind: "dll", dll: "kernel32.dll", count: 1 },
      { kind: "import", dll: "kernel32.dll", name: "VirtualAlloc", rva: 0x3018, refs: 0 },
    ]);
    expect(symbolRows(SYMBOLS, "run").map((r) => r.kind)).toEqual(["exports", "export"]);
  });

  it("matches a DLL name too", () => {
    expect(symbolRows(SYMBOLS, "advapi").map((r) => r.kind)).toEqual(["dll", "import"]);
    expect(symbolRows(SYMBOLS, "nothing-like-this")).toEqual([]);
    expect(symbolRows({ imports: [], exports: [] }, "")).toEqual([]);
  });
});

function region(name: string, size: number): MemoryRegion {
  return { name, kind: "section", rva: 0x1000, vsize: size, offset: 0, size, perm: "R--", entropy: 1 };
}

describe("mapSegments", () => {
  it("gives every region a visible share and sums to 100", () => {
    const segs = mapSegments([region("headers", 10), region(".text", 9000), region(".rsrc", 990)]);
    expect(segs.map((s) => s.name)).toEqual(["headers", ".text", ".rsrc"]);
    expect(segs[0]?.percent).toBe(3);
    expect(segs.every((s) => s.percent >= 3)).toBe(true);
    expect(segs.reduce((n, s) => n + s.percent, 0)).toBeCloseTo(100, 6);
    expect(segs[1]!.percent).toBeGreaterThan(segs[2]!.percent);
  });

  it("skips empty regions and handles a single one", () => {
    expect(mapSegments([region(".bss", 0), region(".text", 5)])).toEqual([{ index: 1, name: ".text", percent: 100 }]);
    expect(mapSegments([])).toEqual([]);
  });

  it("stays at 100 when most regions are tiny", () => {
    const segs = mapSegments([region("a", 1), region("b", 1), region("c", 1), region("big", 100000)]);
    expect(segs.reduce((n, s) => n + s.percent, 0)).toBeCloseTo(100, 6);
    expect(segs.slice(0, 3).every((s) => s.percent === 3)).toBe(true);
  });
});

describe("mapSegments with many regions", () => {
  it("never produces a negative or oversized strip", () => {
    const regions = [region("big", 1000000), ...Array.from({ length: 39 }, (_, i) => region(`s${i}`, 1))];
    const segs = mapSegments(regions);
    expect(segs).toHaveLength(40);
    expect(segs.every((s) => s.percent > 0)).toBe(true);
    expect(segs.reduce((n, s) => n + s.percent, 0)).toBeCloseTo(100, 6);
  });
});

describe("errorText", () => {
  const t = (key: string) => ({ "search.bad_pattern": "Bad pattern" })[key] ?? key;

  it("translates message keys and keeps other messages", () => {
    expect(errorText("search.bad_pattern", t)).toBe("Bad pattern");
    expect(errorText("unknown sample abc", t)).toBe("unknown sample abc");
  });
});
