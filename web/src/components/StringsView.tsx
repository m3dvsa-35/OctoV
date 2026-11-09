import { useVirtualizer } from "@tanstack/react-virtual";
import clsx from "clsx";
import { Loader2, Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { StringRow } from "../api/types";
import { hex } from "../lib/format";
import { offsetLabel } from "../lib/triage";
import { setState, useStore, useT } from "../state/store";

const PAGE = 1000;
const ROW_HEIGHT = 24;
const CATEGORIES = [
  "url",
  "domain",
  "ipv4",
  "ipv6",
  "email",
  "path",
  "registry",
  "mutex",
  "command",
  "user_agent",
  "wallet",
  "base64",
] as const;

/** Extracted strings: server-side filter + paging, virtualised rows, double-click → xrefs. */
export function StringsView() {
  const t = useT();
  const sha = useStore((s) => s.active);
  const [category, setCategory] = useState<string | null>(null);
  const [recovered, setRecovered] = useState(false);
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [rows, setRows] = useState<StringRow[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const loading = useRef(false);
  const generation = useRef(0);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(query), 200);
    return () => window.clearTimeout(timer);
  }, [query]);

  const load = async (offset: number, gen: number) => {
    if (!sha || loading.current) return;
    loading.current = true;
    try {
      const page = await api.getStrings(sha, category, debounced, offset, PAGE, recovered ? "recovered" : null);
      if (gen !== generation.current) return;
      setTotal(page.total);
      setRows((prev) => (offset === 0 ? page.items : [...prev, ...page.items]));
    } catch {
      if (gen === generation.current) setTotal(0);
    } finally {
      loading.current = false;
    }
  };

  useEffect(() => {
    const gen = ++generation.current;
    loading.current = false;
    setRows([]);
    setTotal(null);
    void load(0, gen);
  }, [sha, category, debounced, recovered]);

  const parent = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parent.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 30,
  });
  const items = virtual.getVirtualItems();
  const last = items.at(-1)?.index ?? 0;
  useEffect(() => {
    if (total !== null && rows.length < total && last >= rows.length - 50) void load(rows.length, generation.current);
  }, [last, rows.length, total]);

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-1.5 border-b border-line px-2 py-1.5">
        <label className="flex h-7 w-[240px] items-center gap-2 rounded-md border border-line bg-bg px-2 text-faint focus-within:border-accent/60">
          <Search size={13} aria-hidden />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t("strings.search")}
            aria-label={t("strings.search")}
            className="w-full bg-transparent text-[12.5px] text-fg outline-none placeholder:text-faint"
          />
        </label>
        <button
          type="button"
          aria-pressed={recovered}
          onClick={() => setRecovered((v) => !v)}
          className={clsx(
            "h-6 cursor-pointer rounded-full border px-2 text-[11px] transition-colors",
            recovered ? "border-accent bg-accent text-accent-fg" : "border-dashed border-line text-muted hover:text-fg",
          )}
        >
          {t("strings.obfuscated")}
        </button>
        {[null, ...CATEGORIES].map((c) => (
          <button
            key={c ?? "all"}
            type="button"
            aria-pressed={category === c}
            onClick={() => setCategory(c)}
            className={clsx(
              "h-6 cursor-pointer rounded-full border px-2 text-[11px] transition-colors",
              category === c ? "border-accent bg-accent text-accent-fg" : "border-line text-muted hover:text-fg",
            )}
          >
            {c === null ? t("strings.all") : t(`strings.cat.${c}`)}
          </button>
        ))}
        <span className="ml-auto font-mono text-[11px] text-faint">
          {total === null ? <Loader2 size={12} className="animate-spin" aria-hidden /> : t("strings.count", { n: total })}
        </span>
      </div>
      <div className="flex h-7 shrink-0 items-center border-b border-line px-3 text-[11px] font-semibold uppercase tracking-wider text-faint">
        <span className="w-[86px]">{t("strings.offset")}</span>
        <span className="w-[86px]">RVA</span>
        <span className="w-[64px]">{t("strings.section")}</span>
        <span className="w-[56px]">{t("strings.encoding")}</span>
        <span className="w-[64px]">{t("strings.origin")}</span>
        <span className="w-[88px]">{t("strings.category")}</span>
        <span className="w-[48px] text-right">xref</span>
        <span className="pl-4">{t("strings.value")}</span>
      </div>
      <div ref={parent} className="selectable min-h-0 flex-1 overflow-auto font-mono text-[12px]">
        {total === 0 && <p className="p-4 font-sans text-[12.5px] text-muted">{t("strings.none")}</p>}
        <div style={{ height: virtual.getTotalSize(), position: "relative", minWidth: "max-content" }}>
          {items.map((item) => {
            const r = rows[item.index];
            if (!r) return null;
            return (
              <div
                key={item.key}
                title={r.rva !== null ? t("strings.dblclick") : undefined}
                onDoubleClick={(e) =>
                  r.rva !== null &&
                  setState({ xref: { x: e.clientX, y: e.clientY, rva: r.rva, label: JSON.stringify(r.value.slice(0, 40)) } })
                }
                style={{ transform: `translateY(${item.start}px)`, height: ROW_HEIGHT }}
                className="absolute inset-x-0 flex items-center px-3 hover:bg-raised/50"
              >
                <span className="w-[86px] shrink-0 text-asm-addr">{offsetLabel(r.offset)}</span>
                <span className="w-[86px] shrink-0 text-faint">{r.rva !== null ? hex(r.rva, 6) : "—"}</span>
                <span className="w-[64px] shrink-0 truncate text-faint">{r.section ?? "—"}</span>
                <span className="w-[56px] shrink-0 text-faint">{r.encoding}</span>
                <span className={clsx("w-[64px] shrink-0 truncate font-sans text-[11px]", r.origin === "static" ? "text-faint" : "text-accent")}>
                  {t(`strings.origin.${r.origin}`)}
                </span>
                <span className="w-[88px] shrink-0 truncate font-sans text-[11px] text-muted">
                  {r.category ? t(`strings.cat.${r.category}`) : ""}
                </span>
                <span className={clsx("w-[48px] shrink-0 text-right", r.xrefs ? "text-accent" : "text-faint")}>
                  {r.xrefs ?? "—"}
                </span>
                <span className="whitespace-pre pl-4 text-fg">{r.value}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
