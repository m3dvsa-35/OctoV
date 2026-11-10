import { describe, expect, it } from "vitest";
import { apiNames, decompError, firstRva, linesForRva, markLabel, needsJobRefresh, tokenize } from "./pseudoc";

const LINES = [
  { rvas: [] },
  { rvas: [0x1007] },
  { rvas: [0x100d, 0x1010] },
  { rvas: [0x1010] },
  { rvas: [] },
  { rvas: [0x1020] },
];

describe("linesForRva", () => {
  it("returns every line that lists the address", () => {
    expect(linesForRva(LINES, 0x1007)).toEqual([1]);
    expect(linesForRva(LINES, 0x1010)).toEqual([2, 3]);
  });

  it("falls back to the nearest preceding address", () => {
    expect(linesForRva(LINES, 0x1012)).toEqual([2, 3]);
    expect(linesForRva(LINES, 0x100a)).toEqual([1]);
    expect(linesForRva(LINES, 0x9000)).toEqual([5]);
  });

  it("returns nothing before the first address or without lines", () => {
    expect(linesForRva(LINES, 0x1000)).toEqual([]);
    expect(linesForRva([], 0x1000)).toEqual([]);
  });
});

describe("firstRva", () => {
  it("is the lowest address of a line, or null", () => {
    expect(firstRva({ rvas: [0x1010, 0x100d] })).toBe(0x100d);
    expect(firstRva({ rvas: [] })).toBeNull();
  });
});

const APIS = new Set(["CreateRemoteThread", "CreateFile", "send"]);
const kinds = (text: string) => tokenize(text, APIS).map((x) => [x.kind, x.text]);

describe("tokenize", () => {
  it("keeps the text intact", () => {
    const text = '  if (iVar1 == 0x10) { return "a b"; } // done';
    expect(tokenize(text, APIS).map((x) => x.text).join("")).toBe(text);
  });

  it("classifies keywords, types, numbers and strings", () => {
    expect(kinds("  if (uVar1 == 0x1f) return 12;")).toEqual([
      ["plain", "  "],
      ["keyword", "if"],
      ["plain", " ("],
      ["identifier", "uVar1"],
      ["plain", " == "],
      ["number", "0x1f"],
      ["plain", ") "],
      ["keyword", "return"],
      ["plain", " "],
      ["number", "12"],
      ["plain", ";"],
    ]);
    expect(kinds("undefined8 local_10;")[0]).toEqual(["type", "undefined8"]);
    expect(kinds("void * pvVar1")[0]).toEqual(["type", "void"]);
    expect(kinds('puts("x \\" y");')).toContainEqual(["string", '"x \\" y"']);
    expect(kinds("c = 'a';")).toContainEqual(["string", "'a'"]);
  });

  it("marks comments to the end of the line or the closing mark", () => {
    expect(kinds("x = 1; // WARNING: if")).toContainEqual(["comment", "// WARNING: if"]);
    expect(kinds("/* note */ x")[0]).toEqual(["comment", "/* note */"]);
  });

  it("does not read the // of a URL in a symbol name as a comment", () => {
    const toks = tokenize("  p = s_http://x.example/gate.php_140002000;", APIS);
    expect(toks.some((x) => x.kind === "comment")).toBe(false);
    expect(toks.map((x) => x.text).join("")).toBe("  p = s_http://x.example/gate.php_140002000;");
  });

  it("recognises documented API calls, with and without the A/W suffix", () => {
    const call = tokenize("  h = CreateRemoteThread (p,0);", APIS).find((x) => x.kind === "api");
    expect(call).toEqual({ kind: "api", text: "CreateRemoteThread", api: "CreateRemoteThread" });
    const wide = tokenize("CreateFileW(name);", APIS)[0];
    expect(wide).toEqual({ kind: "api", text: "CreateFileW", api: "CreateFile" });
  });

  it("does not call a variable an API", () => {
    expect(kinds("send = 3;")[0]).toEqual(["identifier", "send"]);
    expect(kinds("GetTickCount();")[0]).toEqual(["identifier", "GetTickCount"]);
    expect(kinds("my_send(1);")[0]).toEqual(["identifier", "my_send"]);
  });
});

describe("apiNames", () => {
  it("collects the names that have an explanation", () => {
    const names = apiNames({ "api.CreateFile": "x", "api.send": "y", "ui.hex": "Hex" });
    expect([...names].sort()).toEqual(["CreateFile", "send"]);
  });
});

const t = (key: string) => ({ "decomp.mark.fact": "Finding", "decomp.mark.api": "Sensitive API call", "sev.high": "High" })[key] ?? key;

describe("markLabel", () => {
  it("spells out the severity of a finding", () => {
    expect(markLabel({ kind: "fact", fact_id: "rule:EVA-001:0x10", severity: "high" }, t)).toBe("Finding · High");
  });

  it("names the API", () => {
    expect(markLabel({ kind: "api", api: "CreateRemoteThread", family: "thread_inject" }, t)).toBe(
      "Sensitive API call · CreateRemoteThread",
    );
  });
});

describe("decompError", () => {
  const tr = (key: string) => ({ "decomp.failed": "The decompiler failed", "decomp.timeout": "Too slow" })[key] ?? key;

  it("translates a message key", () => {
    expect(decompError("decomp.timeout", tr)).toBe("Too slow");
  });

  it("keeps the detail after the key", () => {
    expect(decompError("decomp.failed: worker exited with 3", tr)).toBe("The decompiler failed: worker exited with 3");
  });

  it("leaves other messages alone", () => {
    expect(decompError("unknown sample abc", tr)).toBe("unknown sample abc");
  });
});

describe("needsJobRefresh", () => {
  it("is true when the decompiler stopped being available behind the UI's back", () => {
    expect(needsJobRefresh("decomp.failed: worker exited with 3")).toBe(true);
    expect(needsJobRefresh("decomp.not_ready")).toBe(true);
  });

  it("is false for answers about one address", () => {
    expect(needsJobRefresh("decomp.no_function")).toBe(false);
    expect(needsJobRefresh("decomp.analysing")).toBe(false);
    expect(needsJobRefresh("decomp.timeout")).toBe(false);
  });
});
