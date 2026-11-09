import { useVirtualizer } from "@tanstack/react-virtual";
import clsx from "clsx";
import { FileBox, Loader2, Search, SquareFunction, X } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { formatBytes, hex } from "../lib/format";
import { closeSample, navigate, selectSample, useStore, useT } from "../state/store";
import { Tabs } from "./ui";

type SideTab = "samples" | "functions";

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
        ]}
      />
      {tab === "samples" ? <SampleList /> : <FunctionList />}
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
  const { functions, discovery, current } = useStore((s) => ({
    functions: s.functions,
    discovery: s.discovery,
    current: s.nav?.fn ?? null,
  }));
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? functions.filter((f) => f.name.toLowerCase().includes(q) || hex(f.start).includes(q)) : functions;
  }, [functions, query]);
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
                style={{ transform: `translateY(${row.start}px)`, height: row.size }}
                className={clsx(
                  "absolute inset-x-0 flex cursor-pointer items-center gap-2 rounded-md px-2 text-left font-mono text-[12px] transition-colors",
                  fn.start === current ? "bg-accent/15 text-fg" : "text-muted hover:bg-raised/60 hover:text-fg",
                )}
              >
                <span className="truncate">{fn.name}</span>
                {fn.is_entry && (
                  <span className="rounded bg-accent/15 px-1 text-[10px] text-accent">
                    {t("functions.entry")}
                  </span>
                )}
                <span className="ml-auto text-[10.5px] text-faint">{fn.blocks}b</span>
              </button>
            );
          })}
        </div>
      </div>
    </>
  );
}
