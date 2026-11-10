import { useVirtualizer } from "@tanstack/react-virtual";
import { Loader2, Search } from "lucide-react";
import { useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type { SearchKind, SearchResult } from "../api/types";
import { hex } from "../lib/format";
import { errorText } from "../lib/search";
import { gotoOffset, navigate, useStore, useT } from "../state/store";
import { Button, Segmented } from "./ui";

const ROW_HEIGHT = 22;
const LIMIT = 500;
const KINDS: SearchKind[] = ["bytes", "text", "imm"];

interface Saved {
  sha: string;
  kind: SearchKind;
  query: string;
  result: SearchResult | null;
  error: string | null;
}

// Clicking a hit may replace this tab with the code view: keep the last search to come back to.
let saved: Saved | null = null;

export function SearchView() {
  const t = useT();
  const sha = useStore((s) => s.active);
  const mine = saved && saved.sha === sha ? saved : null;
  const [kind, setKind] = useState<SearchKind>(mine?.kind ?? "bytes");
  const [query, setQuery] = useState(mine?.query ?? "");
  const [result, setResult] = useState<SearchResult | null>(mine?.result ?? null);
  const [error, setError] = useState<string | null>(mine?.error ?? null);
  const [busy, setBusy] = useState(false);

  const remember = (next: Partial<Saved>) => {
    if (sha) saved = { sha, kind, query, result, error, ...next };
  };
  const run = async () => {
    if (!sha || busy) return;
    setBusy(true);
    try {
      const out = await api.search(sha, kind, query, LIMIT);
      setResult(out);
      setError(null);
      remember({ result: out, error: null });
    } catch (err) {
      const message = err instanceof ApiError ? err.message : String(err);
      setResult(null);
      setError(message);
      remember({ result: null, error: message });
    } finally {
      setBusy(false);
    }
  };

  const items = result?.items ?? [];
  const parent = useRef<HTMLDivElement>(null);
  const rows = useVirtualizer({
    count: items.length,
    getScrollElement: () => parent.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 30,
  });

  return (
    <div className="flex h-full flex-col" aria-label={t("ui.search")}>
      <form
        className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line px-3 py-2"
        onSubmit={(e) => {
          e.preventDefault();
          void run();
        }}
      >
        <Segmented<SearchKind>
          label={t("ui.search")}
          value={kind}
          onChange={(k) => {
            setKind(k);
            setResult(null);
            setError(null);
          }}
          options={KINDS.map((id) => ({ id, label: t(`search.kind.${id}`) }))}
        />
        <label className="flex h-7 min-w-[220px] flex-1 items-center gap-2 rounded-md border border-line bg-bg px-2 text-faint focus-within:border-accent/60">
          <Search size={13} aria-hidden />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t(`search.hint.${kind}`)}
            aria-label={t(`search.hint.${kind}`)}
            spellCheck={false}
            className="w-full bg-transparent font-mono text-[12.5px] text-fg outline-none placeholder:font-sans placeholder:text-faint"
          />
        </label>
        <Button variant="primary" type="submit" disabled={busy || !query.trim()}>
          {busy ? <Loader2 size={14} className="animate-spin" aria-hidden /> : t("search.run")}
        </Button>
      </form>
      <div className="shrink-0 px-3 py-1 text-[11.5px] text-muted" role="status">
        {error
          ? errorText(error, t)
          : result
            ? result.truncated
              ? t("search.truncated", { n: items.length })
              : items.length
                ? t("search.count", { n: items.length })
                : t("search.none")
            : t(`search.hint.${kind}`)}
      </div>
      <div ref={parent} className="selectable min-h-0 flex-1 overflow-auto font-mono text-[12.5px]">
        <div style={{ height: rows.getTotalSize(), position: "relative", minWidth: "max-content" }}>
          {rows.getVirtualItems().map((item) => {
            const hit = items[item.index];
            if (!hit) return null;
            return (
              <button
                key={item.key}
                type="button"
                style={{ transform: `translateY(${item.start}px)`, height: ROW_HEIGHT }}
                onClick={() => {
                  if (hit.rva !== null) void navigate(hit.rva, { view: hit.function !== null ? "disasm" : "hex" });
                  else if (hit.offset !== null) gotoOffset(hit.offset);
                }}
                className="absolute inset-x-0 flex cursor-pointer items-center gap-3 whitespace-pre px-3 text-left hover:bg-raised/60"
              >
                <span className="w-[84px] shrink-0 text-asm-addr">
                  {hit.rva !== null ? hex(hit.rva, 8) : `@${hex(hit.offset ?? 0, 6)}`}
                </span>
                <span className="w-[180px] shrink-0 truncate text-muted">
                  {hit.function_name ?? (hit.rva === null ? t("search.not_mapped") : "—")}
                </span>
                <span className="text-fg">{hit.text}</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
