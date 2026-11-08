import { useVirtualizer } from "@tanstack/react-virtual";
import clsx from "clsx";
import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import { hex, hexRow, parseAddress } from "../lib/format";
import { useStore, useT } from "../state/store";

const ROW = 16;
const CHUNK = 64 * 1024;
const ROW_HEIGHT = 20;

/** Bytes are fetched lazily in 64 KiB chunks; only visible rows are rendered. */
function useChunks(sha: string | null) {
  const cache = useRef(new Map<number, Uint8Array>());
  const pending = useRef(new Set<number>());
  const [total, setTotal] = useState(0);
  const [, bump] = useState(0);

  useEffect(() => {
    cache.current.clear();
    pending.current.clear();
    setTotal(0);
    if (!sha) return;
    void api.readBytes(sha, 0, CHUNK).then((c) => {
      cache.current.set(0, Uint8Array.from(atob(c.data), (ch) => ch.charCodeAt(0)));
      setTotal(c.total);
    });
  }, [sha]);

  const get = (offset: number): Uint8Array | null => {
    const base = offset - (offset % CHUNK);
    const chunk = cache.current.get(base);
    if (chunk) return chunk.subarray(offset - base, offset - base + ROW);
    if (sha && !pending.current.has(base)) {
      pending.current.add(base);
      void api.readBytes(sha, base, CHUNK).then((c) => {
        cache.current.set(base, Uint8Array.from(atob(c.data), (ch) => ch.charCodeAt(0)));
        pending.current.delete(base);
        bump((n) => n + 1);
      });
    }
    return null;
  };
  return { total, get };
}

export function HexView() {
  const t = useT();
  const { sha, nav } = useStore((s) => ({ sha: s.active, nav: s.nav }));
  const { total, get } = useChunks(sha);
  const [focus, setFocus] = useState<number | null>(null);
  const [input, setInput] = useState("");
  const parent = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({
    count: Math.ceil(total / ROW),
    getScrollElement: () => parent.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 24,
  });

  useEffect(() => {
    if (nav?.offset != null) setFocus(nav.offset);
  }, [nav]);
  useEffect(() => {
    if (focus !== null && total) virtual.scrollToIndex(Math.floor(focus / ROW), { align: "center" });
  }, [focus, total, virtual]);

  return (
    <div className="flex h-full flex-col">
      <form
        className="flex shrink-0 items-center gap-2 border-b border-line px-3 py-1.5"
        onSubmit={(e) => {
          e.preventDefault();
          const value = parseAddress(input);
          if (value !== null) setFocus(Math.min(value, Math.max(0, total - 1)));
        }}
      >
        <span className="text-[11.5px] text-muted">{t("ui.goto_offset")}</span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="0x400"
          className="h-6 w-32 rounded border border-line bg-bg px-2 font-mono text-[12px] outline-none focus:border-accent/60"
        />
        <span className="ml-auto font-mono text-[11px] text-faint">
          {focus !== null ? `${t("ui.offset")} ${hex(focus)} · ` : ""}
          {total.toLocaleString()} B
        </span>
      </form>
      <div ref={parent} className="selectable min-h-0 flex-1 overflow-auto font-mono text-[12.5px]">
        <div style={{ height: virtual.getTotalSize(), position: "relative", minWidth: "max-content" }}>
          {virtual.getVirtualItems().map((item) => {
            const offset = item.index * ROW;
            const bytes = get(offset);
            const row = bytes ? hexRow(bytes, offset) : null;
            const inRow = focus !== null && focus >= offset && focus < offset + ROW;
            return (
              <div
                key={item.key}
                className={clsx("absolute inset-x-0 flex items-center gap-6 px-4", inRow && "bg-accent/10")}
                style={{ transform: `translateY(${item.start}px)`, height: ROW_HEIGHT }}
              >
                <span className="text-asm-addr">{hex(offset, 8)}</span>
                <span className="flex gap-[0.45em]">
                  {row
                    ? row.hex.map((b, i) => (
                        <span
                          key={i}
                          className={clsx(
                            i === 8 && "ml-2",
                            focus === offset + i ? "rounded-sm bg-accent text-accent-fg" : b === "00" ? "text-faint" : "text-fg",
                          )}
                        >
                          {b}
                        </span>
                      ))
                    : <span className="text-faint">…</span>}
                </span>
                <span className="text-muted">{row?.ascii}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
