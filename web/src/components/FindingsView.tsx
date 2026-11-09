import clsx from "clsx";
import { ChevronRight, Crosshair, ShieldCheck } from "lucide-react";
import { Fragment, useState } from "react";
import type { Severity } from "../api/types";
import { hex } from "../lib/format";
import { navigate, useStore, useT } from "../state/store";
import { Empty, SeverityBadge } from "./ui";

const LEVELS: Severity[] = ["high", "medium", "low", "info"];

export function FindingsView() {
  const t = useT();
  const findings = useStore((s) => s.findings);
  const [open, setOpen] = useState<string | null>(null);
  const [hidden, setHidden] = useState<Set<Severity>>(new Set());
  if (!findings.length) return <Empty icon={ShieldCheck} title={t("ui.no_findings")} />;
  const counts = Object.fromEntries(LEVELS.map((l) => [l, findings.filter((f) => f.severity === l).length]));
  const rows = findings.filter((f) => !hidden.has(f.severity));

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-center gap-1.5 border-b border-line px-3 py-1.5">
        {LEVELS.map((level) => (
          <button
            key={level}
            type="button"
            aria-pressed={!hidden.has(level)}
            onClick={() =>
              setHidden((h) => {
                const next = new Set(h);
                if (next.has(level)) next.delete(level);
                else next.add(level);
                return next;
              })
            }
            className={clsx(
              "cursor-pointer rounded-md transition-opacity",
              hidden.has(level) && "opacity-35",
            )}
          >
            <SeverityBadge severity={level} label={`${t(`sev.${level}`)} ${counts[level]}`} />
          </button>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full table-fixed text-left text-[12.5px]">
          <colgroup>
            <col className="w-8" />
            <col className="w-[104px]" />
            <col className="w-[190px]" />
            <col />
            <col className="w-[150px]" />
            <col className="w-[110px]" />
          </colgroup>
          <thead className="sticky top-0 z-10 bg-panel text-[11px] uppercase tracking-wide text-faint">
            <tr className="border-b border-line">
              <th />
              <th className="py-2 font-medium">{t("indicators.column.severity")}</th>
              <th className="font-medium">{t("indicators.column.id")}</th>
              <th className="font-medium">{t("indicators.column.description")}</th>
              <th className="font-medium">MITRE</th>
              <th className="pr-3 font-medium">{t("ui.location")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => {
              const expanded = open === f.id;
              return (
                <Fragment key={f.id}>
                  <tr
                    onClick={() => setOpen(expanded ? null : f.id)}
                    onDoubleClick={() => f.rva !== null && void navigate(f.rva)}
                    className="cursor-pointer border-b border-line/60 transition-colors hover:bg-raised/50"
                  >
                    <td className="pl-2 text-faint">
                      <ChevronRight
                        size={14}
                        aria-hidden
                        className={clsx("transition-transform", expanded && "rotate-90")}
                      />
                    </td>
                    <td className="py-1.5">
                      <SeverityBadge severity={f.severity} label={t(`sev.${f.severity}`)} />
                    </td>
                    <td className="truncate font-mono text-[11.5px]">
                      <span className="text-fg">{f.id}</span>
                    </td>
                    <td className="truncate pr-3">
                      {f.kind === "rule" && <span className="mr-2 font-medium">{f.name}</span>}
                      <span className="text-muted">{f.description}</span>
                    </td>
                    <td className="truncate font-mono text-[11.5px] text-muted" title={f.mitre.map((m) => `${m} ${f.mitre_names[m]}`).join("\n")}>
                      {f.mitre.join(", ") || "—"}
                    </td>
                    <td className="pr-3">
                      {f.rva !== null ? (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            void navigate(f.rva as number);
                          }}
                          className="inline-flex cursor-pointer items-center gap-1 font-mono text-[11.5px] text-accent hover:underline"
                        >
                          <Crosshair size={12} aria-hidden />
                          {hex(f.rva)}
                        </button>
                      ) : f.offset !== null ? (
                        <span className="font-mono text-[11.5px] text-muted">off {hex(f.offset)}</span>
                      ) : (
                        <span className="text-faint">—</span>
                      )}
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="border-b border-line/60 bg-bg/60">
                      <td />
                      <td colSpan={5} className="py-2.5 pr-3">
                        {f.mitre.length > 0 && (
                          <div className="mb-2 flex flex-wrap gap-1.5">
                            {f.mitre.map((m) => (
                              <span key={m} className="rounded bg-raised px-1.5 py-0.5 text-[11.5px]">
                                <span className="font-mono text-muted">{m}</span> {f.mitre_names[m]}
                              </span>
                            ))}
                          </div>
                        )}
                        <div className="text-[11px] font-semibold uppercase tracking-wide text-faint">
                          {t("ui.evidence")}
                        </div>
                        <ul className="selectable mt-1 space-y-0.5 font-mono text-[11.5px] text-muted">
                          {f.evidence.slice(0, 12).map((e, i) => (
                            <li key={i} className="flex gap-3">
                              {e.type && <span className="w-14 shrink-0 text-faint">{e.type}</span>}
                              {e.rva != null ? (
                                <button
                                  type="button"
                                  onClick={() => void navigate(e.rva as number)}
                                  className="w-20 shrink-0 cursor-pointer text-left text-accent hover:underline"
                                >
                                  {hex(e.rva)}
                                </button>
                              ) : e.offset != null ? (
                                <span className="w-20 shrink-0">off {hex(e.offset)}</span>
                              ) : null}
                              <span className="break-all text-fg/85">{e.detail}</span>
                            </li>
                          ))}
                        </ul>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
