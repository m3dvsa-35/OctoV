import { Binary, Code2, Loader2, X } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { XrefRow } from "../api/types";
import { hex } from "../lib/format";
import { navigate, setState, useStore, useT } from "../state/store";
import { IconButton } from "./ui";

/** Popover listing every code reference to an address; a row jumps to the referencing instruction. */
export function XrefPopover() {
  const t = useT();
  const { xref, sha } = useStore((s) => ({ xref: s.xref, sha: s.active }));
  const [rows, setRows] = useState<XrefRow[] | null>(null);

  useEffect(() => {
    setRows(null);
    if (!xref || !sha) return;
    let live = true;
    void api.xrefsTo(sha, xref.rva).then(
      (r) => live && setRows(r),
      () => live && setRows([]),
    );
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setState({ xref: null });
    window.addEventListener("keydown", onKey);
    return () => {
      live = false;
      window.removeEventListener("keydown", onKey);
    };
  }, [xref, sha]);

  if (!xref) return null;
  const close = () => setState({ xref: null });
  const jump = (rva: number, view?: "disasm" | "hex") => {
    close();
    void navigate(rva, view ? { view } : {});
  };
  return (
    <div className="fixed inset-0 z-[55]" onMouseDown={close}>
      <div
        role="dialog"
        aria-label={t("xref.title", { addr: xref.label })}
        onMouseDown={(e) => e.stopPropagation()}
        style={{ left: Math.min(xref.x, window.innerWidth - 340), top: Math.min(xref.y, window.innerHeight - 300) }}
        className="fixed flex max-h-[280px] w-[330px] flex-col rounded-lg border border-line bg-panel shadow-2xl"
      >
        <div className="flex h-9 items-center gap-2 border-b border-line px-3">
          <span className="truncate text-[12.5px] font-semibold">{t("xref.title", { addr: xref.label })}</span>
          <IconButton icon={X} label={t("ui.close")} className="ml-auto" onClick={close} />
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-1">
          {rows === null ? (
            <div className="flex justify-center p-3 text-muted">
              <Loader2 size={15} className="animate-spin" aria-hidden />
            </div>
          ) : rows.length === 0 ? (
            <p className="p-2.5 text-[12px] text-muted">{t("xref.none")}</p>
          ) : (
            rows.map((r) => (
              <button
                key={`${r.src}:${r.kind}`}
                type="button"
                onClick={() => jump(r.src, "disasm")}
                className="flex h-7 w-full cursor-pointer items-center gap-2 rounded px-2 text-left font-mono text-[12px] hover:bg-raised"
              >
                <Code2 size={13} className="text-muted" aria-hidden />
                <span className="text-asm-addr">{hex(r.src, 8)}</span>
                <span className="truncate">{r.func_name ?? "—"}</span>
                <span className="ml-auto text-[10.5px] text-faint">{r.kind}</span>
              </button>
            ))
          )}
        </div>
        <div className="border-t border-line p-1">
          <button
            type="button"
            onClick={() => jump(xref.rva, "hex")}
            className="flex h-7 w-full cursor-pointer items-center gap-2 rounded px-2 text-left text-[12px] text-muted hover:bg-raised hover:text-fg"
          >
            <Binary size={13} aria-hidden />
            {t("xref.show_hex")}
          </button>
        </div>
      </div>
    </div>
  );
}
