import type { BlockData, EdgeKind, FunctionData } from "../api/types";

export const CHAR_W = 7.25; // JetBrains Mono at 12px
export const LINE_H = 17;
export const PAD_X = 12;
export const HEADER_H = 24;
export const MAX_LINES = 18;

export interface ElkNode {
  id: string;
  width: number;
  height: number;
  x?: number;
  y?: number;
}

export interface ElkEdge {
  id: string;
  sources: string[];
  targets: string[];
  kind: EdgeKind;
  sections?: { startPoint: Pt; endPoint: Pt; bendPoints?: Pt[] }[];
}

export interface Pt {
  x: number;
  y: number;
}

export interface ElkGraph {
  id: string;
  layoutOptions: Record<string, string>;
  children: ElkNode[];
  edges: ElkEdge[];
}

export function blockLines(block: BlockData): string[] {
  const lines = block.instructions
    .slice(0, MAX_LINES)
    // Mirror the rendered row (AsmText pads the mnemonic to 7 columns) so widths fit.
    .map(
      (i) =>
        `${i.address.toString(16).padStart(8, "0")}  ${i.mnemonic.padEnd(7)} ${i.target !== null ? `0x${i.target.toString(16)}` : i.operands}` +
        (i.comment ? ` ; ${i.comment}` : ""),
    );
  if (block.instructions.length > MAX_LINES) lines.push(`… +${block.instructions.length - MAX_LINES}`);
  return lines;
}

export function toElkGraph(fn: FunctionData): ElkGraph {
  const ids = new Set(fn.blocks.map((b) => b.start));
  const children = fn.blocks.map((b) => {
    const lines = blockLines(b);
    const longest = Math.max(12, ...lines.map((l) => l.length));
    return {
      id: String(b.start),
      width: Math.ceil(longest * CHAR_W + PAD_X * 2),
      height: HEADER_H + Math.max(1, lines.length) * LINE_H + 10,
    };
  });
  const edges: ElkEdge[] = [];
  for (const b of fn.blocks) {
    b.successors.forEach((e, i) => {
      if (!ids.has(e.target)) return;
      edges.push({
        id: `${b.start}-${e.target}-${i}`,
        sources: [String(b.start)],
        targets: [String(e.target)],
        kind: e.kind,
      });
    });
  }
  return {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "DOWN",
      "elk.edgeRouting": "ORTHOGONAL",
      "elk.layered.spacing.nodeNodeBetweenLayers": "48",
      "elk.spacing.nodeNode": "36",
      "elk.spacing.edgeNode": "18",
      "elk.spacing.edgeEdge": "10",
      "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
      "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
      "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
    },
    children,
    edges,
  };
}
