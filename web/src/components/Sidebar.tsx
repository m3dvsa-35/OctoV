import { useVirtualizer } from "@tanstack/react-virtual";
import clsx from "clsx";
import { FileBox, Library, Loader2, Search, SquareFunction, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import type { Symbols } from "../api/types";
import { symbolRows } from "../lib/search";
import { formatBytes, hex } from "../lib/format";
import { libraryCount, visibleFunctions } from "../lib/triage";
import { closeSample, navigate, selectSample, setState, useStore, useT } from "../state/store";
import { openAnnotateMenu } from "./AnnotateMenu";
import { Tabs } from "./ui";

type SideTab = "samples" | "functions" | "symbols";

export function Sidebar() {
  const t = useT();
  const [tab, setTab] = useState<SideTab>("samples");
  const { samples, functions } = useStore((s) => ({
    samples: s.samples.length,
    functions: s.functions.length,
  }));
  return (
    <aside className="flex h-full flex-col overflow-hidden bg-panel">
      <Tabs<SideTab>
        value={tab}
        onChange={setTab}
        items={[
          { id: "samples", label: t("ui.samples"), icon: FileBox, badge: samples },
          { id: "functions", label: t("ui.functions"), icon: SquareFunction, badge: functions },
          { id: "symbols", label: t("ui.symbols"), icon: Library },
        ]}
      />
      {tab === "samples" ? <SampleList /> : tab === "functions" ? <FunctionList /> : <SymbolList />}
    </aside>
  );
}

function SampleList() {
  const t = useT();
  const { samples, active } = useStore((s) => ({ samples: s.samples, active: s.active }));
  if (!samples.length) {
    return <p className="p-4 text-[12.5px] leading-relaxed text-muted">{t("ui.no_samples")}</p>;
  }
  return (
    <ul className="min-h-0 flex-1 overflow-auto p-1.5">
      {samples.map((s) => (
        <li key={s.sha256}>
          <div
            role="button"
            tabIndex={0}
            onClick={() => void selectSample(s.sha256)}
            onKeyDown={(e) => e.key === "Enter" && void selectSample(s.sha256)}
            className={clsx(
              "group flex cursor-pointer flex-col gap-1 rounded-md px-2.5 py-2 transition-colors",
              s.sha256 === active ? "bg-raised" : "hover:bg-raised/60",
            )}
          >
            <div className="flex items-center gap-2">
              <span className="truncate text-[12.5px] font-medium">{s.name}</span>
              <span className="rounded bg-bg px-1 font-mono text-[10px] uppercase text-muted">
                {s.format}
              </span>
              <button
                type="button"
                aria-label={t("ui.close")}
                onClick={(e) => {
                  e.stopPropagation();
                  void closeSample(s.sha256);
                }}
                className="ml-auto hidden cursor-pointer rounded p-0.5 text-faint hover:text-fg group-hover:block"
              >
                <X size={13} aria-hidden />
              </button>
            </div>
            <div className="flex items-center gap-2 font-mono text-[10.5px] text-faint">
              <span>{s.sha256.slice(0, 12)}</span>
              <span>{formatBytes(s.size)}</span>
              <span className="ml-auto flex gap-1.5">
                {s.counts.high > 0 && <span className="text-sev-high">{s.counts.high}H</span>}
                {s.counts.medium > 0 && <span className="text-sev-medium">{s.counts.medium}M</span>}
                {s.counts.low > 0 && <span className="text-sev-low">{s.counts.low}L</span>}
              </span>
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

function FunctionList() {
  const t = useT();
  const { functions, discovery, current, findings, hideLibrary } = useStore((s) => ({
    hideLibrary: s.hideLibrary,
    functions: s.functions,
    discovery: s.discovery,
    current: s.nav?.fn ?? null,
    findings: s.findings,
  }));
  const capaCount = useMemo(() => {
    const counts = new Map<number, number>();
    for (const f of findings) {
      const start = f.kind === "capability" ? f.evidence[0]?.rva : null;
      if (start != null) counts.set(start, (counts.get(start) ?? 0) + 1);
    }
    return counts;
  }, [findings]);
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => visibleFunctions(functions, query, hideLibrary), [functions, query, hideLibrary]);
  const libraries = useMemo(() => libraryCount(functions), [functions]);
  const parent = useRef<HTMLDivElement>(null);
  const rows = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parent.current,
    estimateSize: () => 28,
    overscan: 20,
  });

  if (discovery?.state === "running") {
    return (
      <div className="flex items-center gap-2 p-4 text-[12.5px] text-muted">
        <Loader2 size={14} className="animate-spin" aria-hidden />
        {t("ui.discovering")}
      </div>
    );
  }
  return (
    <>
      <label className="m-2 flex h-7 items-center gap-2 rounded-md border border-line bg-bg px-2 text-faint focus-within:border-accent/60">
        <Search size={13} aria-hidden />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("ui.search_functions")}
          className="w-full bg-transparent text-[12.5px] text-fg outline-none placeholder:text-faint"
        />
      </label>
      {libraries > 0 && (
        <label className="mx-2 mb-1.5 flex cursor-pointer items-center gap-1.5 text-[11.5px] text-muted">
          <input
            type="checkbox"
            checked={hideLibrary}
            onChange={(e) => setState({ hideLibrary: e.target.checked })}
          />
          {t("functions.hide_library", { n: libraries })}
        </label>
      )}
      <div ref={parent} className="min-h-0 flex-1 overflow-auto px-1.5 pb-2">
        <div style={{ height: rows.getTotalSize(), position: "relative" }}>
          {rows.getVirtualItems().map((row) => {
            const fn = filtered[row.index];
            if (!fn) return null;
            return (
              <button
                key={fn.start}
                type="button"
                onClick={() => void navigate(fn.start)}
                onContextMenu={(e) => openAnnotateMenu(e, fn.start, fn.start)}
                title={fn.library ? t("functions.library_hint") : fn.suggested ? t("functions.suggested_hint") : undefined}
                style={{ transform: `translateY(${row.start}px)`, height: row.size }}
                className={clsx(
                  "absolute inset-x-0 flex cursor-pointer items-center gap-2 rounded-md px-2 text-left font-mono text-[12px] transition-colors",
                  fn.start === current ? "bg-accent/15 text-fg" : "text-muted hover:bg-raised/60 hover:text-fg",
                )}
              >
                <span className={clsx("truncate", fn.suggested && "italic", fn.library && fn.start !== current && "text-faint")}>
                  {fn.name}
                </span>
                {fn.library && (
                  <span className="shrink-0 rounded border border-line px-1 text-[10px] text-faint">
                    {t("functions.library")}
                  </span>
                )}
                {fn.suggested && <span className="text-[10px] text-faint">{t("functions.suggested")}</span>}
                {fn.is_entry && (
                  <span className="rounded bg-accent/15 px-1 text-[10px] text-accent">
                    {t("functions.entry")}
                  </span>
                )}
                {capaCount.get(fn.start) && (
                  <span className="ml-auto rounded bg-raised px-1 text-[10px] text-muted" title="capa">
                    capa {capaCount.get(fn.start)}
                  </span>
                )}
                <span className={clsx("text-[10.5px] text-faint", !capaCount.get(fn.start) && "ml-auto")}>{fn.blocks}b</span>
              </button>
            );
          })}
        </div>
      </div>
    </>
  );
}

/** Imports by DLL (click: who references it) and exports (click: go there). */
function SymbolList() {
  const t = useT();
  const { sha, ready } = useStore((s) => ({ sha: s.active, ready: s.discovery?.state === "done" }));
  const [symbols, setSymbols] = useState<Symbols | null>(null);
  const [query, setQuery] = useState("");
  useEffect(() => {
    setSymbols(null);
    if (!sha) return;
    let live = true;
    // Asked again once functions are known: the reference counts need the xrefs.
    void api.symbols(sha).then(
      (out) => live && setSymbols(out),
      () => live && setSymbols({ imports: [], exports: [] }),
    );
    return () => {
      live = false;
    };
  }, [sha, ready]);
  const rows = useMemo(() => (symbols ? symbolRows(symbols, query) : []), [symbols, query]);
  const parent = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parent.current,
    estimateSize: () => 26,
    overscan: 20,
  });
  if (!symbols) {
    return (
      <div className="flex items-center gap-2 p-4 text-[12.5px] text-muted">
        <Loader2 size={14} className="animate-spin" aria-hidden />
      </div>
    );
  }
  if (!symbols.imports.length && !symbols.exports.length) {
    return <p className="p-4 text-[12.5px] leading-relaxed text-muted">{t("symbols.none")}</p>;
  }
  return (
    <>
      <label className="m-2 flex h-7 items-center gap-2 rounded-md border border-line bg-bg px-2 text-faint focus-within:border-accent/60">
        <Search size={13} aria-hidden />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t("symbols.filter")}
          className="w-full bg-transparent text-[12.5px] text-fg outline-none placeholder:text-faint"
        />
      </label>
      <div ref={parent} className="min-h-0 flex-1 overflow-auto px-1.5 pb-2">
        <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
          {virtual.getVirtualItems().map((item) => {
            const row = rows[item.index];
            if (!row) return null;
            const style = { transform: `translateY(${item.start}px)`, height: item.size };
            if (row.kind === "dll" || row.kind === "exports") {
              return (
                <div
                  key={item.key}
                  style={style}
                  className="absolute inset-x-0 flex items-center gap-2 px-2 text-[11px] font-semibold uppercase tracking-wide text-faint"
                >
                  <span className="truncate">{row.kind === "dll" ? row.dll : t("symbols.exports")}</span>
                  <span className="ml-auto font-mono font-normal">{row.count}</span>
                </div>
              );
            }
            const refs = row.kind === "import" ? row.refs : null;
            return (
              <button
                key={item.key}
                type="button"
                style={style}
                title={refs !== null ? t("symbols.refs", { n: refs }) : hex(row.rva)}
                onClick={(e) => {
                  if (row.kind === "export") void navigate(row.rva);
                  else setState({ xref: { x: e.clientX, y: e.clientY, rva: row.rva, label: row.name } });
                }}
                className={clsx(
                  "absolute inset-x-0 flex cursor-pointer items-center gap-2 rounded-md px-2 pl-4 text-left font-mono text-[12px] transition-colors hover:bg-raised/60 hover:text-fg",
                  refs === 0 ? "text-faint" : "text-muted",
                )}
              >
                <span className="truncate">{row.name}</span>
                {refs !== null && <span className="ml-auto text-[10.5px] text-faint">{refs}</span>}
              </button>
            );
          })}
        </div>
      </div>
    </>
  );
}
