import clsx from "clsx";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import type { MemoryMapData, MemoryRegion } from "../api/types";
import { formatBytes, hex } from "../lib/format";
import { mapSegments } from "../lib/search";
import { gotoOffset, navigate, useStore, useT } from "../state/store";

const KIND_CLASS: Record<MemoryRegion["kind"], string> = {
  headers: "bg-raised",
  section: "bg-accent/25",
  overlay: "bg-sev-medium/25",
  gap: "bg-bg",
  raw: "bg-accent/25",
};

function open(region: MemoryRegion): void {
  if (region.rva !== null) void navigate(region.rva, { view: "hex" });
  else gotoOffset(region.offset);
}

/** The file from first to last byte: headers, sections, overlay. Text carries the meaning. */
export function MemoryMap() {
  const t = useT();
  const sha = useStore((s) => s.active);
  const [map, setMap] = useState<MemoryMapData | null>(null);
  useEffect(() => {
    setMap(null);
    if (!sha) return;
    let live = true;
    void api.memoryMap(sha).then(
      (m) => live && setMap(m),
      () => live && setMap(null),
    );
    return () => {
      live = false;
    };
  }, [sha]);
  const segments = useMemo(() => (map ? mapSegments(map.regions) : []), [map]);
  if (!map || !segments.length) return null;
  return (
    <div>
      <div className="flex h-9 w-full overflow-hidden rounded-md border border-line" role="list" aria-label={t("map.title")}>
        {segments.map((seg) => {
          const region = map.regions[seg.index];
          if (!region) return null;
          return (
            <button
              key={seg.index}
              type="button"
              role="listitem"
              onClick={() => open(region)}
              title={`${region.name} · ${t(`map.kind.${region.kind}`)} · ${hex(region.offset)} · ${formatBytes(region.size)} · ${region.perm} · ${t("ui.entropy")} ${region.entropy.toFixed(2)}`}
              style={{ width: `${seg.percent}%` }}
              className={clsx(
                "flex min-w-0 cursor-pointer flex-col justify-center border-r border-line px-1 text-left font-mono text-[10px] leading-tight last:border-r-0 hover:brightness-125",
                KIND_CLASS[region.kind],
              )}
            >
              <span className="truncate text-fg">{region.name}</span>
              <span className="truncate text-muted">{region.kind === "section" || region.kind === "raw" ? region.perm : t(`map.kind.${region.kind}`)}</span>
            </button>
          );
        })}
      </div>
      <p className="mt-1.5 text-[11px] text-faint">{t("map.hint", { size: formatBytes(map.size) })}</p>
    </div>
  );
}
