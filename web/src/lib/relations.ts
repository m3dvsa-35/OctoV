import type { ApiUse, RelationNode, Relations } from "../api/types";

export const NODE_W = 236;
export const ROW_TITLE = 26;
export const ROW_META = 18;
export const ROW_CHIPS = 24;
export const ROW_HINT = 16;
export const NODE_PAD = 12;
export const MAX_CHIPS = 3;

export interface FamilyChip {
  family: string | null; // null = APIs outside OctoV's families
  count: number;
  suspicious: boolean;
  names: string[];
}

/** One chip per API family: suspicious families first, uncategorised APIs last. */
export function familyChips(apis: ApiUse[], max = MAX_CHIPS): { shown: FamilyChip[]; more: number } {
  const chips: FamilyChip[] = [];
  for (const api of apis) {
    const chip = chips.find((c) => c.family === api.family);
    if (chip) {
      chip.count += 1;
      chip.names.push(api.name);
    } else chips.push({ family: api.family, count: 1, suspicious: api.suspicious, names: [api.name] });
  }
  const rank = (c: FamilyChip) => (c.suspicious ? 0 : c.family !== null ? 1 : 2);
  chips.sort((a, b) => rank(a) - rank(b));
  return { shown: chips.slice(0, max), more: Math.max(0, chips.length - max) };
}

/** The ranking score in words (same weights as one high / one medium fact). */
export function scoreWord(score: number): "high" | "medium" | "low" | null {
  if (score >= 30) return "high";
  if (score >= 12) return "medium";
  return score > 0 ? "low" : null;
}

export function hasMeta(node: RelationNode): boolean {
  return node.score > 0 || node.is_entry || node.is_export || node.recursive;
}

export function nodeSize(node: RelationNode): { width: number; height: number } {
  let height = NODE_PAD + ROW_TITLE;
  if (hasMeta(node)) height += ROW_META;
  if (node.apis.length) height += ROW_CHIPS;
  if (node.hidden_callers || node.hidden_callees) height += ROW_HINT;
  return { width: NODE_W, height };
}

export interface RelEdge {
  id: string;
  sources: string[];
  targets: string[];
  onPath: boolean;
}

export interface RelGraph {
  id: string;
  layoutOptions: Record<string, string>;
  children: { id: string; width: number; height: number }[];
  edges: RelEdge[];
}

/** ELK input: callers end up on the left, callees on the right. */
export function toRelationsGraph(rel: Relations): RelGraph {
  const shown = new Set(rel.nodes.map((n) => n.start));
  const onPath = new Set<string>();
  for (let i = 0; i + 1 < rel.path.length; i++) onPath.add(`${rel.path[i]}-${rel.path[i + 1]}`);
  return {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.edgeRouting": "ORTHOGONAL",
      "elk.layered.spacing.nodeNodeBetweenLayers": "64",
      "elk.spacing.nodeNode": "18",
      "elk.spacing.edgeNode": "14",
      "elk.spacing.edgeEdge": "8",
      "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
      "elk.layered.cycleBreaking.strategy": "DEPTH_FIRST",
    },
    children: rel.nodes.map((n) => ({ id: String(n.start), ...nodeSize(n) })),
    edges: rel.edges
      .filter((e) => shown.has(e.src) && shown.has(e.dst))
      .map((e) => {
        const id = `${e.src}-${e.dst}`;
        return { id, sources: [String(e.src)], targets: [String(e.dst)], onPath: onPath.has(id) };
      }),
  };
}

/** One line on how execution gets to the centre: it is a way in itself, or the path's root. */
export function reachText(
  rel: Pick<Relations, "center" | "nodes" | "path" | "path_root">,
  t: (key: string, vars?: Record<string, string | number>) => string,
): string {
  const center = rel.nodes.find((n) => n.start === rel.center);
  if (center?.is_entry) return t("relations.is_entry");
  if (center?.is_export) return t("relations.is_export");
  const calls = pathLength(rel.path);
  if (!rel.path_root || calls === 0) return t("relations.no_path");
  return rel.path_root.kind === "entry"
    ? t("relations.entry_path", { n: calls })
    : t("relations.export_path", { n: calls, name: rel.path_root.name });
}

/** Number of calls on the path from the entry point (or an export) to the function. */
export function pathLength(path: number[]): number {
  return Math.max(0, path.length - 1);
}
