import {
  Background,
  BaseEdge,
  Controls,
  type Edge,
  type EdgeProps,
  Handle,
  MiniMap,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from "@xyflow/react";
import clsx from "clsx";
import ELK from "elkjs/lib/elk-api.js";
import { Loader2, Network } from "lucide-react";
import { memo, useEffect, useMemo, useState } from "react";
import type { BlockData, EdgeKind, FunctionData } from "../api/types";
import { hex } from "../lib/format";
import { HEADER_H, LINE_H, MAX_LINES, type ElkEdge, type Pt, toElkGraph } from "../lib/cfgLayout";
import { useFunctionData } from "../state/hooks";
import { annotationKey, getState, navigate, useStore, useT } from "../state/store";
import { openAnnotateMenu } from "./AnnotateMenu";
import { AsmText } from "./Asm";
import { Empty } from "./ui";

const MAX_GRAPH_BLOCKS = 600;

// Layout runs in a worker so large functions never block the UI thread.
const elk = new ELK({
  workerFactory: () =>
    new Worker(new URL("elkjs/lib/elk-worker.min.js", import.meta.url), { type: "module" }),
});

type BlockNodeData = { block: BlockData; active: number | null; selected: boolean };
type FlowEdgeData = { points: Pt[]; kind: EdgeKind };

const EDGE_STYLE: Record<EdgeKind, { color: string; dash?: string; label?: string }> = {
  true: { color: "var(--edge-true)", label: "T" },
  false: { color: "var(--edge-false)", dash: "5 4", label: "F" },
  jump: { color: "var(--edge-jump)" },
  fallthrough: { color: "var(--muted)" },
};

const BlockNode = memo(function BlockNode({ data }: NodeProps<Node<BlockNodeData>>) {
  const { block, active, selected } = data;
  const shown = block.instructions.slice(0, MAX_LINES);
  return (
    <div
      className={clsx(
        "rounded-md border bg-panel font-mono text-[12px] shadow-sm",
        selected ? "border-accent ring-2 ring-accent/30" : "border-line",
      )}
    >
      <Handle type="target" position={Position.Top} className="!opacity-0" />
      <div
        className="flex items-center border-b border-line px-3 text-[11.5px] font-semibold text-muted"
        style={{ height: HEADER_H }}
      >
        loc_{block.start.toString(16)}
        {block.indirect && <span className="ml-2 text-sev-medium">indirect</span>}
      </div>
      <div className="py-1">
        {shown.map((insn) => (
          <div
            key={insn.address}
            onClick={() => void navigate(insn.address, { view: "graph", record: false })}
            onContextMenu={(e) => {
              void navigate(insn.address, { view: "graph", record: false });
              openAnnotateMenu(e, insn.address, getState().nav?.fn ?? null);
            }}
            className={clsx(
              "nodrag cursor-pointer whitespace-pre px-3",
              insn.address === active ? "bg-accent/20" : "hover:bg-raised/60",
            )}
            style={{ height: LINE_H, lineHeight: `${LINE_H}px` }}
          >
            <span className="text-asm-addr">{insn.address.toString(16).padStart(8, "0")}</span>{"  "}
            <AsmText insn={insn} onFollow={(target) => void navigate(target, { view: "graph" })} />
          </div>
        ))}
        {block.instructions.length > MAX_LINES && (
          <div className="px-3 text-faint" style={{ height: LINE_H }}>
            … +{block.instructions.length - MAX_LINES}
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} className="!opacity-0" />
    </div>
  );
});

function ElkEdgeView({ id, data, markerEnd }: EdgeProps<Edge<FlowEdgeData>>) {
  if (!data) return null;
  const style = EDGE_STYLE[data.kind];
  const [first, ...rest] = data.points;
  if (!first) return null;
  const path = `M ${first.x} ${first.y} ` + rest.map((p) => `L ${p.x} ${p.y}`).join(" ");
  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{ stroke: style.color, strokeWidth: 1.6, strokeDasharray: style.dash }}
      />
      {style.label && (
        <text x={first.x + 6} y={first.y + 13} fill={style.color} fontSize={11} fontWeight={700} fontFamily="var(--font-mono)">
          {style.label}
        </text>
      )}
    </>
  );
}

const nodeTypes = { block: BlockNode };
const edgeTypes = { elk: ElkEdgeView };

function useLayout(fn: FunctionData | null) {
  const [layout, setLayout] = useState<{ fn: FunctionData; pos: Map<string, Pt>; edges: ElkEdge[] } | null>(null);
  useEffect(() => {
    if (!fn || fn.blocks.length > MAX_GRAPH_BLOCKS) {
      setLayout(null);
      return;
    }
    let live = true;
    const graph = toElkGraph(fn);
    void elk.layout(graph as never).then((out) => {
      if (!live) return;
      const laid = out as unknown as { children: { id: string; x: number; y: number }[]; edges: ElkEdge[] };
      setLayout({
        fn,
        pos: new Map(laid.children.map((c) => [c.id, { x: c.x, y: c.y }])),
        edges: laid.edges,
      });
    });
    return () => {
      live = false;
    };
  }, [fn]);
  return layout?.fn === fn ? layout : null;
}

function Graph({ fn }: { fn: FunctionData }) {
  const nav = useStore((s) => s.nav);
  const layout = useLayout(fn);
  const flow = useReactFlow();
  const activeBlock = useMemo(
    () => (nav ? fn.blocks.find((b) => b.start <= nav.rva && nav.rva < b.end)?.start ?? null : null),
    [fn, nav],
  );

  const nodes = useMemo<Node<BlockNodeData>[]>(
    () =>
      layout
        ? fn.blocks.map((block) => ({
            id: String(block.start),
            type: "block",
            position: layout.pos.get(String(block.start)) ?? { x: 0, y: 0 },
            data: { block, active: nav?.rva ?? null, selected: block.start === activeBlock },
            draggable: false,
          }))
        : [],
    [layout, fn, nav, activeBlock],
  );
  const edges = useMemo<Edge<FlowEdgeData>[]>(
    () =>
      layout
        ? layout.edges.map((e) => {
            const s = e.sections?.[0];
            const points = s ? [s.startPoint, ...(s.bendPoints ?? []), s.endPoint] : [];
            return {
              id: e.id,
              source: e.sources[0] ?? "",
              target: e.targets[0] ?? "",
              type: "elk",
              data: { points, kind: e.kind },
              markerEnd: { type: "arrowclosed" as never, color: EDGE_STYLE[e.kind].color, width: 14, height: 14 },
            };
          })
        : [],
    [layout],
  );

  // Centre the block that contains the current address.
  useEffect(() => {
    if (!layout || activeBlock === null) return;
    const pos = layout.pos.get(String(activeBlock));
    if (pos) void flow.setCenter(pos.x + 160, pos.y + 60, { zoom: Math.max(flow.getZoom(), 0.8), duration: 250 });
  }, [layout, activeBlock, flow]);

  if (!layout) {
    return (
      <div className="flex h-full items-center justify-center text-muted">
        <Loader2 size={18} className="animate-spin" aria-hidden />
      </div>
    );
  }
  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      fitView={activeBlock === null}
      minZoom={0.1}
      maxZoom={2}
      nodesConnectable={false}
      proOptions={{ hideAttribution: true }}
      onlyRenderVisibleElements
    >
      <Background gap={24} size={1} color="var(--line)" />
      <Controls showInteractive={false} />
      <MiniMap
        pannable
        zoomable
        nodeColor="var(--raised)"
        nodeStrokeColor="var(--line)"
        maskColor="color-mix(in srgb, var(--bg) 65%, transparent)"
        bgColor="var(--panel)"
      />
    </ReactFlow>
  );
}

export function GraphView() {
  const t = useT();
  const { sha, nav } = useStore((s) => ({ sha: s.active, nav: s.nav }));
  const fn = useFunctionData(sha, nav?.fn ?? null);
  if (!nav || nav.fn === null) {
    return <Empty icon={Network} title={t("ui.no_function")} body={t("ui.graph_hint")} />;
  }
  if (!fn) return null;
  if (fn.blocks.length > MAX_GRAPH_BLOCKS) {
    return (
      <Empty
        icon={Network}
        title={t("graph.too_large", { start: fn.start.toString(16), count: fn.blocks.length })}
      />
    );
  }
  return (
    <ReactFlowProvider>
      <div className="relative h-full outline-none" tabIndex={0} onKeyDown={annotationKey} aria-label={t("ui.graph")}>
        <div className="pointer-events-none absolute left-3 top-2 z-10 rounded bg-panel/90 px-2 py-1 font-mono text-[11.5px] text-muted">
          {fn.name} · {fn.blocks.length} blocks · {hex(fn.start)}
        </div>
        <Graph fn={fn} />
      </div>
    </ReactFlowProvider>
  );
}
