import { describe, expect, it } from "vitest";
import { formatBytes, hex, hexRow, parseAddress, severityRank, tokenizeOperands } from "./format";

describe("hex", () => {
  it("pads and lowercases", () => {
    expect(hex(0x1a, 8)).toBe("0000001a");
    expect(hex(0x1000)).toBe("0x1000");
  });
});

describe("parseAddress", () => {
  it.each([
    ["0x1000", 0x1000],
    ["1000h", 0x1000],
    ["sub_19c0", 0x19c0],
    ["loc_100b", 0x100b],
    ["  0X2A ", 0x2a],
    ["1f", 0x1f],
  ])("parses %s", (input, expected) => {
    expect(parseAddress(input)).toBe(expected);
  });
  it.each(["", "zz", "0x", "sub_", "-5"])("rejects %s", (input) => {
    expect(parseAddress(input)).toBeNull();
  });
});

describe("hexRow", () => {
  it("formats offset, bytes and printable ascii", () => {
    const bytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x41]);
    const row = hexRow(bytes, 0x40);
    expect(row.offset).toBe("00000040");
    expect(row.hex).toEqual(["4d", "5a", "90", "00", "41"]);
    expect(row.ascii).toBe("MZ..A");
  });
});

describe("tokenizeOperands", () => {
  it("separates registers, numbers and punctuation", () => {
    expect(tokenizeOperands("qword ptr [rip + 0x2501], rax")).toEqual([
      { kind: "keyword", text: "qword ptr" },
      { kind: "punct", text: " [" },
      { kind: "register", text: "rip" },
      { kind: "punct", text: " + " },
      { kind: "number", text: "0x2501" },
      { kind: "punct", text: "], " },
      { kind: "register", text: "rax" },
    ]);
  });
  it("handles empty operands", () => {
    expect(tokenizeOperands("")).toEqual([]);
  });
});

describe("severityRank", () => {
  it("orders high first", () => {
    const sorted = ["low", "high", "info", "medium"].sort((a, b) => severityRank(a) - severityRank(b));
    expect(sorted).toEqual(["high", "medium", "low", "info"]);
  });
});

describe("formatBytes", () => {
  it("uses binary units", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(360448)).toBe("352.0 KiB");
    expect(formatBytes(10 * 1024 * 1024)).toBe("10.0 MiB");
  });
});
