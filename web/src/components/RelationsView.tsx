import {
  Background,
  BaseEdge,
  Controls,
  type Edge,
  type EdgeProps,
  Handle,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from "@xyflow/react";
import clsx from "clsx";
import { Loader2, Waypoints, Zap } from "lucide-react";
import { memo, useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../api/client";
import type { RelationNode, Relations } from "../api/types";
import { hex } from "../lib/format";
import {
  familyChips,
  hasMeta,
  NODE_W,
  pathLength,
  ROW_CHIPS,
  ROW_HINT,
  ROW_META,
  ROW_TITLE,
  scoreWord,
  toRelationsGraph,
  type RelEdge,
} from "../lib/relations";
import { getState, navigate, useStore, useT } from "../state/store";
import { elk } from "./elk";
import { Empty } from "./ui";

interface Pt {
  x: number;
  y: number;
}
type LaidEdge = RelEdge & { sections?: { startPoint: Pt; endPoint: Pt; bendPoints?: Pt[] }[] };
type FnNodeData = { node: RelationNode };
type RelEdgeData = { points: Pt[]; onPath: boolean; label: string };

const SCORE_CLASS = { high: "text-sev-high", medium: "text-sev-medium", low: "text-sev-low" } as const;

const FnNode = memo(function FnNode({ data }: NodeProps<Node<FnNodeData>>) {
  const t = useT();
  const { node } = data;
  const word = scoreWord(node.score);
  const chips = familyChips(node.apis);
  const center = node.role === "center";
  return (
    <div
      title={`${node.name} · ${hex(node.start)}`}
      onClick={() => void navigate(node.start, { view: getState().main })}
      onDoubleClick={() => void navigate(node.start, { view: "disasm" })}
      style={{ width: NODE_W }}
      className={clsx(
        "nodrag cursor-pointer rounded-md border bg-panel px-2.5 py-1.5 text-[11.5px] shadow-sm transition-colors hover:bg-raised/60",
        center ? "border-accent ring-2 ring-accent/30" : "border-line",
      )}
    >
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <div className="flex items-center gap-1.5 font-mono text-[12px]" style={{ height: ROW_TITLE - 6 }}>
        <span className={clsx("truncate", center ? "font-semibold text-fg" : "text-fg")}>{node.name}</span>
      </div>
      {hasMeta(node) && (
        <div className="flex items-center gap-1.5 text-[10.5px]" style={{ height: ROW_META }}>
          {word && (
            <span className={clsx("font-semibold", SCORE_CLASS[word])}>
              {t("relations.score", { n: node.score })} · {t(`sev.${word}`)}
            </span>
          )}
          {node.is_entry && <span className="rounded bg-accent/15 px-1 text-accent">{t("functions.entry")}</span>}
          {node.is_export && <span className="rounded bg-raised px-1 text-muted">{t("relations.export")}</span>}
          {node.recursive && <span className="rounded bg-raised px-1 text-muted">{t("relations.recursive")}</span>}
        </div>
      )}
      {chips.shown.length > 0 && (
        <div className="flex items-center gap-1 overflow-hidden" style={{ height: ROW_CHIPS }}>
          {chips.shown.map((chip) => (
            <span
              key={chip.family ?? "other"}
              title={chip.names.join(", ")}
              className={clsx(
                "inline-flex shrink-0 items-center gap-0.5 rounded border px-1 font-mono text-[10px]",
                chip.suspicious ? "border-sev-medium/50 font-semibold text-fg" : "border-line text-muted",
              )}
            >
              {chip.suspicious && <Zap size={9} aria-label={t("relations.sensitive")} />}
              {chip.family ?? t("relations.other_apis")}
              {chip.count > 1 && ` ×${chip.count}`}
            </span>
          ))}
          {chips.more > 0 && <span className="text-[10px] text-faint">+{chips.more}</span>}
        </div>
      )}
      {(node.hidden_callers > 0 || node.hidden_callees > 0) && (
        <div className="flex justify-between text-[10px] text-faint" style={{ height: ROW_HINT }}>
          <span>{node.hidden_callers > 0 && t("relations.more_callers", { n: node.hidden_callers })}</span>
          <span>{node.hidden_callees > 0 && t("relations.more_callees", { n: node.hidden_callees })}</span>
        </div>
      )}
      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </div>
  );
});

function RelEdgeView({ id, data, markerEnd }: EdgeProps<Edge<RelEdgeData>>) {
  if (!data) return null;
  const [first, ...rest] = data.points;
  if (!first) return null;
  const path = `M ${first.x} ${first.y} ` + rest.map((p) => `L ${p.x} ${p.y}`).join(" ");
  const color = data.onPath ? "var(--accent)" : "var(--muted)";
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} style={{ stroke: color, strokeWidth: data.onPath ? 2.6 : 1.2 }} />
      {data.onPath && (
        <text x={first.x + 6} y={first.y - 5} fill={color} fontSize={10} fontWeight={700} fontFamily="var(--font-mono)">
          {data.label}
        </text>
      )}
    </>
  );
}

const nodeTypes = { fn: FnNode };
const edgeTypes = { rel: RelEdgeView };

function useLayout(rel: Relations | null) {
  const [layout, setLayout] = useState<{ rel: Relations; pos: Map<string, Pt>; edges: LaidEdge[] } | null>(null);
  useEffect(() => {
    if (!rel) return;
    let live = true;
    void elk.layout(toRelationsGraph(rel) as never).then((out) => {
      if (!live) return;
      const laid = out as unknown as { children: { id: string; x: number; y: number }[]; edges: LaidEdge[] };
      setLayout({ rel, pos: new Map(laid.children.map((c) => [c.id, { x: c.x, y: c.y }])), edges: laid.edges });
    });
    return () => {
      live = false;
    };
  }, [rel]);
  return layout?.rel === rel ? layout : null;
}

function Graph({ rel }: { rel: Relations }) {
  const t = useT();
  const layout = useLayout(rel);
  const flow = useReactFlow();
  const nodes = useMemo<Node<FnNodeData>[]>(
    () =>
      layout
        ? rel.nodes.map((node) => ({
            id: String(node.start),
            type: "fn",
            position: layout.pos.get(String(node.start)) ?? { x: 0, y: 0 },
            data: { node },
            draggable: false,
          }))
        : [],
    [layout, rel],
  );
  const label = t("relations.path");
  const edges = useMemo<Edge<RelEdgeData>[]>(
    () =>
      layout
        ? layout.edges.map((e) => {
            const s = e.sections?.[0];
            return {
              id: e.id,
              source: e.sources[0] ?? "",
              target: e.targets[0] ?? "",
              type: "rel",
              data: { points: s ? [s.startPoint, ...(s.bendPoints ?? []), s.endPoint] : [], onPath: e.onPath, label },
              markerEnd: { type: "arrowclosed" as never, color: e.onPath ? "var(--accent)" : "var(--muted)", width: 14, height: 14 },
            };
          })
        : [],
    [layout, label],
  );
  useEffect(() => {
    if (layout) window.setTimeout(() => void flow.fitView({ padding: 0.15, maxZoom: 1.1, duration: 200 }), 0);
  }, [layout, flow]);

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
      minZoom={0.15}
      maxZoom={1.6}
      nodesConnectable={false}
      zoomOnDoubleClick={false}
      proOptions={{ hideAttribution: true }}
    >
      <Background gap={24} size={1} color="var(--line)" />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}

function Depth({ label, value, onChange }: { label: string; value: number; onChange: (v: number) => void }) {
  return (
    <span className="inline-flex items-center gap-1" role="radiogroup" aria-label={label}>
      <span className="text-faint">{label}</span>
      {[1, 2, 3].map((d) => (
        <button
          key={d}
          type="button"
          role="radio"
          aria-checked={value === d}
          onClick={() => onChange(d)}
          className={clsx(
            "h-5 w-5 cursor-pointer rounded font-mono text-[11px]",
            value === d ? "bg-raised font-semibold text-fg shadow-[inset_0_-2px_0_var(--accent)]" : "text-muted hover:text-fg",
          )}
        >
          {d}
        </button>
      ))}
    </span>
  );
}

export function RelationsView() {
  const t = useT();
  const { sha, fn, annotations, ready } = useStore((s) => ({
    sha: s.active,
    fn: s.nav?.fn ?? null,
    annotations: s.annotationList,
    ready: s.discovery?.state === "done",
  }));
  const [callers, setCallers] = useState(2);
  const [callees, setCallees] = useState(2);
  const [rel, setRel] = useState<Relations | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!sha || fn === null) return;
    let live = true;
    void api.relations(sha, fn, callers, callees).then(
      (out) => {
        if (!live) return;
        setRel(out);
        setError(null);
      },
      (err: unknown) => {
        if (live) setError(err instanceof ApiError ? err.message : String(err));
      },
    );
    return () => {
      live = false;
    };
  }, [sha, fn, callers, callees, annotations, ready]);

  if (fn === null) return <Empty icon={Waypoints} title={t("ui.no_function")} body={t("relations.hint")} />;
  if (error) {
    const waiting = error === "analysis.not_ready";
    return <Empty icon={Waypoints} title={waiting ? t("ui.discovering") : t("ui.relations")} body={waiting ? undefined : error} />;
  }
  const shown = rel && rel.center === fn ? rel : null;
  if (!shown) {
    return (
      <div className="flex h-full items-center justify-center text-muted">
        <Loader2 size={18} className="animate-spin" aria-hidden />
      </div>
    );
  }
  const center = shown.nodes.find((n) => n.start === shown.center);
  const steps = pathLength(shown.path);
  return (
    <div className="flex h-full flex-col" aria-label={t("ui.relations")}>
      <div className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-0.5 border-b border-line px-4 py-1 text-[11.5px] text-muted">
        <span className="font-mono text-fg">{center?.name}</span>
        <span>
          {center?.is_entry
            ? t("relations.is_entry")
            : steps > 0
              ? t("relations.entry_path", { n: steps })
              : t("relations.no_path")}
        </span>
        {shown.truncated && <span className="text-sev-medium">{t("relations.truncated", { n: shown.nodes.length })}</span>}
        <span className="ml-auto flex items-center gap-3">
          <Depth label={t("relations.callers")} value={callers} onChange={setCallers} />
          <Depth label={t("relations.callees")} value={callees} onChange={setCallees} />
        </span>
      </div>
      <div className="min-h-0 flex-1">
        <ReactFlowProvider>
          <Graph rel={shown} />
        </ReactFlowProvider>
      </div>
      <p className="shrink-0 border-t border-line px-4 py-0.5 text-[11px] text-faint">{t("relations.hint")}</p>
    </div>
  );
}
