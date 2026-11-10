import type { MemoryRegion, Symbols } from "../api/types";

export type SymbolRow =
  | { kind: "dll"; dll: string; count: number }
  | { kind: "import"; dll: string; name: string; rva: number; refs: number }
  | { kind: "exports"; count: number }
  | { kind: "export"; name: string; rva: number };

/** Flat rows for the virtualised symbol list; a filter keeps matching names (or whole DLLs). */
export function symbolRows(symbols: Symbols, query: string): SymbolRow[] {
  const q = query.trim().toLowerCase();
  const rows: SymbolRow[] = [];
  for (const group of symbols.imports) {
    const whole = q !== "" && group.dll.toLowerCase().includes(q);
    const kept = group.functions.filter((f) => !q || whole || f.name.toLowerCase().includes(q));
    if (!kept.length) continue;
    rows.push({ kind: "dll", dll: group.dll, count: kept.length });
    for (const f of kept) rows.push({ kind: "import", dll: group.dll, name: f.name, rva: f.rva, refs: f.refs });
  }
  const exports = symbols.exports.filter((e) => !q || e.name.toLowerCase().includes(q));
  if (exports.length) {
    rows.push({ kind: "exports", count: exports.length });
    for (const e of exports) rows.push({ kind: "export", name: e.name, rva: e.rva });
  }
  return rows;
}

export interface MapSegment {
  index: number; // position in the regions list
  name: string;
  percent: number;
}

/** Strip widths: proportional to file size, but never thinner than `minPercent`. */
export function mapSegments(regions: MemoryRegion[], minPercent = 3): MapSegment[] {
  const used = regions.map((r, index) => ({ index, name: r.name, size: r.size })).filter((r) => r.size > 0);
  if (!used.length) return [];
  // with many regions the minimum itself must shrink, or the widths would not fit in 100 %
  minPercent = Math.min(minPercent, 100 / used.length);
  const small = new Set<number>();
  // Raising a small region to the minimum shrinks the others, which can make more of them small.
  for (;;) {
    const large = used.filter((r) => !small.has(r.index));
    const share = 100 - minPercent * small.size;
    const total = large.reduce((n, r) => n + r.size, 0);
    const next = large.filter((r) => (r.size / total) * share < minPercent);
    if (!next.length || next.length === large.length) {
      return used.map((r) => ({
        index: r.index,
        name: r.name,
        percent: small.has(r.index) ? minPercent : total > 0 ? (r.size / total) * share : 100 / used.length,
      }));
    }
    for (const r of next) small.add(r.index);
  }
}

/** API errors that are message keys (`search.bad_pattern`, `analysis.not_ready`) get translated. */
export function errorText(message: string, t: (key: string) => string): string {
  return /^(?:search|analysis)\.[a-z_]+$/.test(message) ? t(message) : message;
}
