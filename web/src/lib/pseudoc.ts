import type { LineMark } from "../api/types";

/** Indexes of the lines showing `rva`: exact matches, else the nearest preceding address. */
export function linesForRva(lines: { rvas: number[] }[], rva: number): number[] {
  let best = -1;
  for (const line of lines) {
    for (const r of line.rvas) if (r <= rva && r > best) best = r;
  }
  if (best < 0) return [];
  const out: number[] = [];
  lines.forEach((line, i) => {
    if (line.rvas.includes(best)) out.push(i);
  });
  return out;
}

export function firstRva(line: { rvas: number[] }): number | null {
  return line.rvas.length ? Math.min(...line.rvas) : null;
}

export type CTokenKind = "keyword" | "type" | "number" | "string" | "comment" | "api" | "identifier" | "plain";

export interface CToken {
  kind: CTokenKind;
  text: string;
  /** Normalised API name (no A/W suffix): the key of its explanation. */
  api?: string;
}

const KEYWORDS = new Set(
  "if else while for do return switch case break continue goto default sizeof struct union enum typedef".split(" "),
);
const TYPES = new Set(
  "void char short int long float double bool unsigned signed byte word dword qword uint ushort ulong uchar longlong ulonglong code wchar_t size_t".split(
    " ",
  ),
);
const TYPE_PATTERN = /^(?:undefined\d*|u?int\d+_t|float\d+)$/;
const TOKEN =
  /(?<!:)\/\/.*$|\/\*.*?(?:\*\/|$)|"(?:[^"\\]|\\.)*"?|'(?:[^'\\]|\\.)*'?|0x[0-9a-fA-F]+|\d+(?:\.\d+)?|[A-Za-z_][A-Za-z0-9_]*|[^A-Za-z0-9_"'/]+|\//g;

function apiOf(name: string, apis: ReadonlySet<string>): string | null {
  if (apis.has(name)) return name;
  const base = name.slice(0, -1);
  return /[a-z][AW]$/.test(name) && apis.has(base) ? base : null;
}

/** Split one pseudo-C line into coloured tokens; `apis` = names that have an explanation. */
export function tokenize(text: string, apis: ReadonlySet<string>): CToken[] {
  const tokens: CToken[] = [];
  for (const match of text.matchAll(TOKEN)) {
    const part = match[0];
    const rest = text.slice((match.index ?? 0) + part.length);
    let token: CToken;
    if (part.startsWith("//") || part.startsWith("/*")) token = { kind: "comment", text: part };
    else if (part.startsWith('"') || part.startsWith("'")) token = { kind: "string", text: part };
    else if (/^\d/.test(part)) token = { kind: "number", text: part };
    else if (/^[A-Za-z_]/.test(part)) {
      const api = /^\s*\(/.test(rest) ? apiOf(part, apis) : null;
      if (api) token = { kind: "api", text: part, api };
      else if (KEYWORDS.has(part)) token = { kind: "keyword", text: part };
      else if (TYPES.has(part) || TYPE_PATTERN.test(part)) token = { kind: "type", text: part };
      else token = { kind: "identifier", text: part };
    } else token = { kind: "plain", text: part };
    const last = tokens.at(-1);
    if (token.kind === "plain" && last?.kind === "plain") last.text += token.text;
    else tokens.push(token);
  }
  return tokens;
}

/** API names that have an `api.<Name>` explanation in the loaded UI strings. */
export function apiNames(strings: Record<string, string>): Set<string> {
  const names = new Set<string>();
  for (const key of Object.keys(strings)) if (key.startsWith("api.")) names.add(key.slice(4));
  return names;
}

/** Marker text: never colour alone, the severity or the API is spelled out. */
export function markLabel(mark: LineMark, t: (key: string) => string): string {
  if (mark.kind === "fact") return `${t("decomp.mark.fact")} · ${t(`sev.${mark.severity}`)}`;
  return `${t("decomp.mark.api")} · ${mark.api}`;
}

/** Errors that mean the job state changed after polling stopped (worker died, sample rerun). */
export function needsJobRefresh(message: string): boolean {
  return message.startsWith("decomp.failed") || message === "decomp.not_ready";
}

/** Decompiler errors arrive as a message key, optionally followed by `: detail`. */
export function decompError(message: string, t: (key: string) => string): string {
  const match = /^((?:decomp|ext)\.[a-z_.]+)(?:: (.*))?$/s.exec(message);
  if (!match?.[1]) return message;
  return match[2] ? `${t(match[1])}: ${match[2]}` : t(match[1]);
}
