import type { AiReport, AiTurn } from "../api/types";

/** The first sentence of an answer (or its beginning), short enough for a tooltip line. */
export function firstSentence(text: string, max = 140): string {
  const flat = text.replace(/\s+/g, " ").trim();
  const end = flat.search(/[.!?](?:\s|$)/);
  const sentence = end >= 0 ? flat.slice(0, end + 1) : flat;
  return sentence.length > max ? `${sentence.slice(0, max - 1)}\u2026` : sentence;
}

/** Function address -> what the AI said about it (story, key points, links, follow-up answers). */
export function aiNotes(report: AiReport | null, turns: AiTurn[] = []): Map<number, string[]> {
  const notes = new Map<number, string[]>();
  const add = (start: number, note: string) => {
    const list = notes.get(start) ?? [];
    if (note && !list.includes(note)) list.push(note);
    notes.set(start, list);
  };
  // the report first, then what follow-up answers added
  const fromTurns = () => {
    for (const turn of turns) for (const start of turn.functions) add(start, firstSentence(turn.answer));
    return notes;
  };
  if (!report) return fromTurns();
  for (const step of report.story) for (const start of step.functions) add(start, step.text);
  for (const point of report.points) for (const start of point.functions) add(start, point.title);
  for (const link of report.links) {
    add(link.from, link.why);
    add(link.to, link.why);
  }
  return fromTurns();
}

export interface OverlayEdge {
  id: string;
  src: number;
  dst: number;
  why: string;
  /** The same two functions are already joined by a call edge: label it, do not draw twice. */
  duplicate: boolean;
}

/** AI links between functions that are both in the picture. `existing` = call edge ids `src-dst`. */
export function overlayEdges(report: AiReport | null, shown: ReadonlySet<number>, existing: ReadonlySet<string>): OverlayEdge[] {
  if (!report) return [];
  return report.links
    .filter((link) => shown.has(link.from) && shown.has(link.to))
    .map((link) => ({
      id: `ai-${link.from}-${link.to}`,
      src: link.from,
      dst: link.to,
      why: link.why,
      duplicate: existing.has(`${link.from}-${link.to}`),
    }));
}

export type Chip =
  | { kind: "function"; label: string; target: number }
  | { kind: "finding"; label: string; target: string }
  | { kind: "ioc"; label: string; target: string };

/** The evidence a statement points at, as clickable chips. */
export function chips(
  item: { functions?: number[]; findings?: string[]; iocs?: string[] },
  names: ReadonlyMap<number, string>,
): Chip[] {
  return [
    ...(item.functions ?? []).map((start): Chip => ({ kind: "function", label: names.get(start) ?? `sub_${start.toString(16)}`, target: start })),
    ...(item.findings ?? []).map((id): Chip => ({ kind: "finding", label: id, target: id })),
    ...(item.iocs ?? []).map((value): Chip => ({ kind: "ioc", label: value, target: value })),
  ];
}

/** `ai.<kind>` job errors and `analysis.*` keys become text; anything else is shown as is. */
export function aiError(message: string, t: (key: string) => string): string {
  const kind = /^ai\.([a-z_]+)$/.exec(message)?.[1];
  if (kind) return t(`ai.error.${kind}`);
  return /^analysis\.[a-z_]+$/.test(message) ? t(message) : message;
}
