import type { Contribution } from "../api/types";

export type Band = "low" | "medium" | "high";

/** Same bands as the Python risk score (0-29 low, 30-59 medium, 60-100 high). */
export function bandOf(score: number): Band {
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export function positiveContributions(rows: Contribution[]): Contribution[] {
  return rows.filter((r) => r.points > 0);
}

export function verdictCounts(rows: { verdict: string | null }[]): { reviewed: number; total: number } {
  return { reviewed: rows.filter((r) => r.verdict !== null).length, total: rows.length };
}
