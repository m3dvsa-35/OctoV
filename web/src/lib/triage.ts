import type { Annotation, Contribution, Severity } from "../api/types";

export type Band = "low" | "medium" | "high";

/** Same bands as the Python risk score (0-29 low, 30-59 medium, 60-100 high). */
export function bandOf(score: number): Band {
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

/** Score clamped to 0..100 and rounded, its band, and the gauge fill percentage. */
export function formatScoreBand(score: number): { score: number; band: Band; percent: number } {
  const s = Math.round(Math.min(100, Math.max(0, score)));
  return { score: s, band: bandOf(s), percent: s };
}

export function positiveContributions(rows: Contribution[]): Contribution[] {
  return rows.filter((r) => r.points > 0);
}

const SEVERITY_ORDER: Severity[] = ["high", "medium", "low", "info"];

/** Positive contributions grouped by severity (high first), keeping row order inside a group. */
export function groupContributions(
  rows: Contribution[],
): { severity: Severity; points: number; rows: Contribution[] }[] {
  const positive = positiveContributions(rows);
  return SEVERITY_ORDER.map((severity) => {
    const group = positive.filter((r) => r.severity === severity);
    return { severity, points: group.reduce((n, r) => n + r.points, 0), rows: group };
  }).filter((g) => g.rows.length > 0);
}

export function verdictCounts(rows: { verdict: string | null }[]): { reviewed: number; total: number } {
  return { reviewed: rows.filter((r) => r.verdict !== null).length, total: rows.length };
}

/** Client-side string filter (same semantics as the server's get_strings). */
export function filterStrings<T extends { value: string; category: string | null }>(
  items: T[],
  { category, query }: { category?: string | null; query?: string },
): T[] {
  const q = query?.trim().toLowerCase() ?? "";
  return items.filter((x) => (!category || x.category === category) && (!q || x.value.toLowerCase().includes(q)));
}

export interface AnnotationIndex {
  comments: Record<number, { id: number; value: string }>;
  bookmarks: Record<number, number>;
  names: Record<number, string>;
}

/** Address-keyed view of the analyst's annotations; the newest annotation wins. */
export function annotationIndex(list: Annotation[]): AnnotationIndex {
  const idx: AnnotationIndex = { comments: {}, bookmarks: {}, names: {} };
  for (const a of [...list].sort((x, y) => x.id - y.id)) {
    if (a.address === null) continue;
    if (a.kind === "comment") idx.comments[a.address] = { id: a.id, value: a.value };
    else if (a.kind === "bookmark") idx.bookmarks[a.address] = a.id;
    else if (a.kind === "name") idx.names[a.address] = a.value;
  }
  return idx;
}
