import { Grid3x3 } from "lucide-react";
import type { MitreRow } from "../api/types";
import { useStore, useT } from "../state/store";
import { Empty, SeverityBadge } from "./ui";

const TACTIC_ORDER = [
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
];

/** Techniques grouped by tactic as tiles; every tile states ID, name, severity and hit count. */
export function MitreView() {
  const t = useT();
  const rows = useStore((s) => s.mitre);
  if (!rows.length) return <Empty icon={Grid3x3} title={t("ui.no_techniques")} />;
  const byTactic = new Map<string, MitreRow[]>();
  for (const row of rows) {
    const key = row.tactic || "other";
    byTactic.set(key, [...(byTactic.get(key) ?? []), row]);
  }
  const tactics = [...byTactic.keys()].sort(
    (a, b) => (TACTIC_ORDER.indexOf(a) + 99) % 99 - (TACTIC_ORDER.indexOf(b) + 99) % 99,
  );
  return (
    <div className="flex h-full gap-3 overflow-auto p-3">
      {tactics.map((tactic) => (
        <section key={tactic} className="flex w-[260px] shrink-0 flex-col gap-2">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-faint">
            {tactic.replace("-", " ")}
          </h3>
          {(byTactic.get(tactic) ?? []).map((row) => (
            <article
              key={row.technique}
              className="rounded-lg border border-line bg-panel p-2.5"
              style={{
                boxShadow: `inset 3px 0 0 var(--sev-${row.severity})`,
              }}
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-[11.5px] text-muted">{row.technique}</span>
                <span className="ml-auto">
                  <SeverityBadge severity={row.severity} label={t(`sev.${row.severity}`)} />
                </span>
              </div>
              <div className="mt-1 text-[12.5px] font-medium">{row.name}</div>
              <div className="mt-1.5 flex items-center gap-2 text-[11px] text-faint">
                <span>{t("ui.hits", { n: row.hits })}</span>
                <span className="truncate font-mono" title={row.sources.join(", ")}>
                  {row.sources.join(", ")}
                </span>
              </div>
            </article>
          ))}
        </section>
      ))}
    </div>
  );
}
