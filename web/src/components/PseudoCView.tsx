import { useVirtualizer } from "@tanstack/react-virtual";
import clsx from "clsx";
import { Braces, Loader2, Play, RotateCw, ShieldAlert, TriangleAlert, Zap } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type { Annotation, Decompiled, LineMark, Severity } from "../api/types";
import { hex, severityRank } from "../lib/format";
import { apiNames, decompError, firstRva, linesForRva, markLabel, needsJobRefresh, tokenize, type CTokenKind } from "../lib/pseudoc";
import { annotationKey, getState, navigate, refreshJobs, runExtension, setState, useStore, useT } from "../state/store";
import { openAnnotateMenu } from "./AnnotateMenu";
import { EngineCard } from "./EngineCard";
import { Button, Empty } from "./ui";

const ROW_HEIGHT = 20;

const TOKEN_CLASS: Record<CTokenKind, string> = {
  keyword: "text-accent",
  type: "text-asm-mnemonic",
  number: "text-asm-number",
  string: "text-sev-low",
  comment: "italic text-asm-comment",
  api: "cursor-help font-semibold text-fg underline decoration-dotted underline-offset-2",
  identifier: "text-fg",
  plain: "text-muted",
};

const SEVERITY_TEXT: Record<Severity, string> = {
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-sev-info",
};

interface Loaded {
  sha: string;
  annotations: Annotation[];
  fn: Decompiled;
  rvas: Set<number>;
}

/** Seconds since `active` became true (the analysing state shows that Ghidra is alive). */
function useElapsed(active: boolean): number {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    if (!active) return;
    const start = Date.now();
    setSeconds(0);
    const timer = window.setInterval(() => setSeconds(Math.round((Date.now() - start) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [active]);
  return seconds;
}

/** Gutter marker: an icon plus the severity (or "API") as text; details in the tooltip. */
function Marker({ marks, titles }: { marks: LineMark[]; titles: Map<string, string> }) {
  const t = useT();
  if (!marks.length) return <span className="w-[64px] shrink-0" />;
  const facts = marks.filter((m) => m.kind === "fact").sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  const top = facts[0];
  const tooltip = marks
    .map((m) => (m.kind === "fact" ? `${markLabel(m, t)} — ${titles.get(m.fact_id) ?? m.fact_id}` : `${markLabel(m, t)} — ${t(`api.${m.api}`)}`))
    .join("\n");
  return (
    <button
      type="button"
      title={tooltip}
      aria-label={tooltip}
      onClick={(e) => {
        e.stopPropagation();
        if (top) setState({ bottom: "findings" });
      }}
      className={clsx(
        "inline-flex w-[64px] shrink-0 items-center gap-1 text-[10.5px] font-semibold uppercase tracking-wide",
        top ? ["cursor-pointer", SEVERITY_TEXT[top.severity]] : "cursor-help text-muted",
      )}
    >
      {top ? <ShieldAlert size={11} aria-hidden /> : <Zap size={11} aria-hidden />}
      {top ? t(`sev.${top.severity}`) : "API"}
    </button>
  );
}

export function PseudoCView() {
  const t = useT();
  const { sha, nav, state, jobError, compact, strings, annotations, extension, findings, fnName } = useStore((s) => ({
    sha: s.active,
    nav: s.nav,
    state: s.triage?.jobs.ghidra?.state ?? null,
    jobError: s.triage?.jobs.ghidra?.error ?? null,
    compact: s.settings.compact,
    strings: s.strings,
    annotations: s.annotationList,
    extension: s.extensions.find((e) => e.id === "ghidra") ?? null,
    findings: s.findings,
    fnName: s.nav?.fn != null ? s.functions.find((f) => f.start === s.nav?.fn)?.name : undefined,
  }));
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [error, setError] = useState<string | null>(null);
  const loadedRef = useRef<Loaded | null>(null);
  const rva = nav?.rva ?? null;
  const askable = state === "queued" || state === "running" || state === "done";

  useEffect(() => {
    if (!sha || rva === null || !askable) return;
    const have = loadedRef.current;
    // Moving inside the function that is already shown needs no new request.
    if (have && have.sha === sha && have.annotations === annotations && have.rvas.has(rva)) {
      setError(null);
      return;
    }
    let live = true;
    void api.decompiled(sha, rva).then(
      (fn) => {
        if (!live) return;
        const rvas = new Set<number>([fn.entry_rva, rva]);
        for (const line of fn.lines) for (const r of line.rvas) rvas.add(r);
        loadedRef.current = { sha, annotations, fn, rvas };
        setLoaded(loadedRef.current);
        setError(null);
      },
      (err: unknown) => {
        const message = err instanceof ApiError ? err.message : String(err);
        if (needsJobRefresh(message)) refreshJobs(); // e.g. the worker crashed: show "Run again"
        if (live) setError(message);
      },
    );
    return () => {
      live = false;
    };
  }, [sha, rva, askable, state, annotations]);

  const fn = loaded && loaded.sha === sha && !error ? loaded.fn : null;
  const apis = useMemo(() => apiNames(strings), [strings]);
  const tokens = useMemo(() => (fn ? fn.lines.map((line) => tokenize(line.text, apis)) : []), [fn, apis]);
  const titles = useMemo(() => new Map(findings.map((f) => [f.id, f.name])), [findings]);
  const current = useMemo(() => new Set(fn && rva !== null ? linesForRva(fn.lines, rva) : []), [fn, rva]);
  const firstCurrent = current.size ? Math.min(...current) : -1;
  const analysing = !fn && (state === "queued" || state === "running");
  const elapsed = useElapsed(analysing);

  const parent = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({
    count: fn?.lines.length ?? 0,
    getScrollElement: () => parent.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 30,
  });
  useEffect(() => {
    if (firstCurrent >= 0) virtual.scrollToIndex(firstCurrent, { align: "center" });
  }, [firstCurrent, virtual, fn]);

  if (state === null || state === "unavailable") {
    if (extension && !extension.ready) {
      return (
        <div className="p-4">
          <EngineCard ext={extension} />
        </div>
      );
    }
    return <Empty icon={Braces} title={t("ui.pseudo_c")} body={t(jobError ?? "decomp.not_ready")} />;
  }
  if (state === "idle" || state === "failed") {
    return (
      <Empty
        icon={state === "failed" ? TriangleAlert : Braces}
        title={state === "failed" ? t("decomp.failed") : t("ui.pseudo_c")}
        body={state === "failed" ? (jobError ?? "") : t("decomp.not_ready")}
      >
        <Button
          variant="primary"
          icon={state === "failed" ? RotateCw : Play}
          onClick={() => void runExtension("ghidra", false)}
        >
          {state === "failed" ? t("ext.rerun") : t("ext.run")}
        </Button>
      </Empty>
    );
  }
  if (!nav) return <Empty icon={Braces} title={t("ui.no_function")} body={t("ui.no_function_body")} />;
  if (analysing) {
    return (
      <Empty icon={Loader2} title={t("decomp.analysing")} body={t("ext.ghidra.adds")}>
        <span className="font-mono text-[12px] text-muted" role="status">
          {t(`triage.job.${state}`)} · {elapsed} s
        </span>
      </Empty>
    );
  }
  if (!fn) {
    if (error) return <Empty icon={Braces} title={t("ui.pseudo_c")} body={decompError(error, t)} />;
    return (
      <div className="flex h-full items-center justify-center text-muted">
        <Loader2 size={18} className="animate-spin" aria-hidden />
      </div>
    );
  }

  const elsewhere = fn.octov_function !== null && fn.octov_function !== fn.entry_rva;
  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-0.5 border-b border-line px-4 py-1 text-[11.5px] text-muted">
        <span className="font-mono text-fg">{fn.name}</span>
        <span className="font-mono text-faint">{hex(fn.entry_rva)}</span>
        {elsewhere && (
          <span>{t("decomp.octov_function", { name: fnName ?? `sub_${(fn.octov_function ?? 0).toString(16)}` })}</span>
        )}
        {fn.warnings.length > 0 && (
          <span className="inline-flex items-center gap-1 text-sev-medium" title={fn.warnings.join("\n")}>
            <TriangleAlert size={11} aria-hidden /> {t("decomp.warnings", { n: fn.warnings.length })}
          </span>
        )}
        {!compact && (
          <details className="ml-auto max-w-full">
            <summary className="cursor-pointer select-none text-right hover:text-fg">{t("decomp.help.title")}</summary>
            <p className="mt-1 max-w-[640px] pb-1 leading-relaxed">{t("decomp.help.body")}</p>
          </details>
        )}
      </div>
      <div
        ref={parent}
        tabIndex={0}
        onKeyDown={annotationKey}
        aria-label={t("ui.pseudo_c")}
        className="selectable min-h-0 flex-1 overflow-auto font-mono text-[12.5px] leading-5 outline-none"
      >
        <div style={{ height: virtual.getTotalSize(), position: "relative", minWidth: "max-content" }}>
          {virtual.getVirtualItems().map((item) => {
            const line = fn.lines[item.index];
            if (!line) return null;
            const target = firstRva(line);
            return (
              <div
                key={item.key}
                style={{ transform: `translateY(${item.start}px)`, height: ROW_HEIGHT }}
                onClick={() => target !== null && void navigate(target, { record: false, view: getState().main })}
                onContextMenu={(e) => {
                  if (target === null) return;
                  void navigate(target, { record: false, view: getState().main });
                  openAnnotateMenu(e, target, nav.fn);
                }}
                className={clsx(
                  "absolute inset-x-0 flex items-center whitespace-pre px-3",
                  current.has(item.index) ? "bg-accent/15 shadow-[inset_2px_0_0_var(--accent)]" : "hover:bg-raised/50",
                  target !== null && "cursor-pointer",
                )}
              >
                <Marker marks={line.marks} titles={titles} />
                <span className="mr-3 w-[34px] shrink-0 text-right text-asm-addr">{item.index + 1}</span>
                <span>
                  {(tokens[item.index] ?? []).map((tok, i) => (
                    <span key={i} className={TOKEN_CLASS[tok.kind]} title={tok.api ? `${tok.api} — ${t(`api.${tok.api}`)}` : undefined}>
                      {tok.text}
                    </span>
                  ))}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
