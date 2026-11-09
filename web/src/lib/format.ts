export function hex(value: number, width?: number): string {
  const digits = value.toString(16);
  return width === undefined ? `0x${digits}` : digits.padStart(width, "0");
}

/** Parse user input such as `0x1000`, `1000h`, `sub_19c0`, `loc_100b` or bare hex. */
export function parseAddress(input: string): number | null {
  let text = input.trim().toLowerCase();
  const label = /^(?:sub|loc)_([0-9a-f]+)$/.exec(text);
  if (label?.[1]) text = label[1];
  else if (text.startsWith("0x")) text = text.slice(2);
  else if (text.endsWith("h")) text = text.slice(0, -1);
  if (!/^[0-9a-f]+$/.test(text)) return null;
  return Number.parseInt(text, 16);
}

export interface HexRow {
  offset: string;
  hex: string[];
  ascii: string;
}

export function hexRow(bytes: Uint8Array, offset: number): HexRow {
  const hexBytes: string[] = [];
  let ascii = "";
  for (const b of bytes) {
    hexBytes.push(b.toString(16).padStart(2, "0"));
    ascii += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
  }
  return { offset: hex(offset, 8), hex: hexBytes, ascii };
}

export type TokenKind = "keyword" | "register" | "number" | "punct" | "symbol";
export interface Token {
  kind: TokenKind;
  text: string;
}

const REGISTER =
  /^(?:[re]?[abcd]x|[abcd][lh]|[re]?(?:si|di|sp|bp|ip)|[sd]il|[sb]pl|r(?:[89]|1[0-5])[dwb]?|[c-gs]s|[xyz]mm\d{1,2}|st\d?|cr\d|dr\d)$/;

/** Split an Intel-syntax operand string into coloured tokens. */
export function tokenizeOperands(operands: string): Token[] {
  const tokens: Token[] = [];
  const re = /(byte|word|dword|qword|xmmword|ymmword|tbyte|fword)\s+ptr|0x[0-9a-f]+|\b\d+\b|[a-z_][a-z0-9_]*|[^a-z0-9_]+/gi;
  for (const match of operands.matchAll(re)) {
    const text = match[0];
    let kind: TokenKind;
    if (/ptr$/i.test(text)) kind = "keyword";
    else if (/^(0x[0-9a-f]+|\d+)$/i.test(text)) kind = "number";
    else if (REGISTER.test(text.toLowerCase())) kind = "register";
    else if (/^[a-z_]/i.test(text)) kind = "symbol";
    else kind = "punct";
    const last = tokens.at(-1);
    if (kind === "punct" && last?.kind === "punct") last.text += text;
    else tokens.push({ kind, text });
  }
  return tokens;
}

const SEVERITY_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2, info: 3 };

export function severityRank(severity: string): number {
  return SEVERITY_ORDER[severity] ?? 9;
}

export function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
}
