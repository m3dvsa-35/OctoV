import { useVirtualizer } from "@tanstack/react-virtual";
import clsx from "clsx";
import { Bookmark, Code2 } from "lucide-react";
import { useEffect, useMemo, useRef } from "react";
import type { InstructionData } from "../api/types";
import { hex } from "../lib/format";
import { useFunctionData, useLinear } from "../state/hooks";
import { annotationKey, getState, navigate, useStore, useT } from "../state/store";
import { openAnnotateMenu } from "./AnnotateMenu";
import { AsmText } from "./Asm";
import { Empty } from "./ui";

type Row =
  | { kind: "label"; address: number; text: string }
  | { kind: "insn"; insn: InstructionData }
  | { kind: "gap" };

const ROW_HEIGHT = 20;

export function DisasmView() {
  const t = useT();
  const { sha, nav, discovery, bookmarks } = useStore((s) => ({
    sha: s.active,
    nav: s.nav,
    discovery: s.discovery,
    bookmarks: s.annotations.bookmarks,
  }));
  const fn = useFunctionData(sha, nav?.fn ?? null);
  const linear = useLinear(sha, nav?.rva ?? null, nav !== null && nav.fn === null);

  const rows = useMemo<Row[]>(() => {
    if (fn) {
      const out: Row[] = [{ kind: "label", address: fn.start, text: `${fn.name}:` }];
      fn.blocks.forEach((b, i) => {
        if (i > 0) out.push({ kind: "gap" }, { kind: "label", address: b.start, text: `loc_${b.start.toString(16)}:` });
        for (const insn of b.instructions) out.push({ kind: "insn", insn });
      });
      return out;
    }
    if (linear.length && nav) {
      return [
        { kind: "label", address: nav.rva, text: t("disasm.raw", { rva: nav.rva.toString(16) }) },
        ...linear.map((insn) => ({ kind: "insn" as const, insn })),
      ];
    }
    return [];
  }, [fn, linear, nav, t]);

  const current = useMemo(() => {
    if (!nav) return -1;
    return rows.findIndex(
      (r) => r.kind === "insn" && r.insn.address <= nav.rva && nav.rva < r.insn.address + r.insn.bytes.length / 2,
    );
  }, [rows, nav]);

  const parent = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parent.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 30,
  });

  useEffect(() => {
    if (current >= 0) virtual.scrollToIndex(current, { align: "center" });
  }, [current, virtual]);

  if (!nav) {
    return (
      <Empty
        icon={Code2}
        title={discovery?.state === "running" ? t("ui.discovering") : t("ui.no_function")}
        body={t("ui.no_function_body")}
      />
    );
  }

  return (
    <div
      ref={parent}
      tabIndex={0}
      onKeyDown={annotationKey}
      aria-label={t("ui.disassembly")}
      className="selectable h-full overflow-auto font-mono text-[12.5px] leading-5 outline-none"
    >
      <div style={{ height: virtual.getTotalSize(), position: "relative", minWidth: "max-content" }}>
        {virtual.getVirtualItems().map((item) => {
          const row = rows[item.index];
          if (!row) return null;
          const style = { transform: `translateY(${item.start}px)`, height: ROW_HEIGHT };
          if (row.kind === "gap") return <div key={item.key} className="absolute inset-x-0" style={style} />;
          if (row.kind === "label") {
            return (
              <div key={item.key} className="absolute inset-x-0 flex items-center px-4 font-semibold text-fg" style={style}>
                <span className="mr-3 w-[76px] text-asm-addr">{hex(row.address, 8)}</span>
                {row.text}
              </div>
            );
          }
          const { insn } = row;
          const active = item.index === current;
          return (
            <div
              key={item.key}
              style={style}
              onClick={() => void navigate(insn.address, { record: false, view: getState().main })}
              onDoubleClick={() => insn.target !== null && void navigate(insn.target)}
              onContextMenu={(e) => {
                void navigate(insn.address, { record: false, view: getState().main });
                openAnnotateMenu(e, insn.address, nav.fn);
              }}
              className={clsx(
                "absolute inset-x-0 flex items-center whitespace-pre px-4",
                active ? "bg-accent/15 shadow-[inset_2px_0_0_var(--accent)]" : "hover:bg-raised/50",
              )}
            >
              <span className="w-3 shrink-0" title={bookmarks[insn.address] !== undefined ? t("annotate.bookmarked") : undefined}>
                {bookmarks[insn.address] !== undefined && (
                  <Bookmark size={10} className="fill-accent text-accent" aria-label={t("annotate.bookmarked")} />
                )}
              </span>
              <span className="mr-3 w-[76px] shrink-0 text-asm-addr">{hex(insn.address, 8)}</span>
              <span className="mr-3 w-[150px] shrink-0 truncate text-faint">
                {insn.bytes.match(/../g)?.join(" ")}
              </span>
              <span className="pl-4">
                <AsmText insn={insn} onFollow={(target) => void navigate(target)} />
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
