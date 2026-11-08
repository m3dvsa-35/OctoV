import clsx from "clsx";
import { Check, Copy, Crosshair, ExternalLink, Loader2, PackageOpen, ShieldOff, X } from "lucide-react";
import { useState } from "react";
import { api } from "../api/client";
import type { CapabilityRow, Verdict } from "../api/types";
import { hex } from "../lib/format";
import { positiveContributions, verdictCounts } from "../lib/triage";
import { getState, navigate, notify, selectSample, setState, setVerdict, useStore, useT } from "../state/store";
import { SeverityBadge } from "./ui";

const BAND_COLOR = { low: "var(--sev-low)", medium: "var(--sev-medium)", high: "var(--sev-high)" };

function Card({ title, children, right }: { title: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-panel">
      <div className="flex items-center border-b border-line px-3.5 py-2">
        <h3 className="text-[11px] font-semibold uppercase tracking-wider text-faint">{title}</h3>
        <div className="ml-auto">{right}</div>
      </div>
      <div className="p-3.5">{children}</div>
    </section>
  );
}

function VerdictButtons({ factId, verdict }: { factId: string; verdict: Verdict | null }) {
  const t = useT();
  const opts: { v: Verdict; icon: typeof Check; label: string }[] = [
    { v: "confirmed", icon: Check, label: t("triage.verdict.confirm") },
    { v: "false_positive", icon: X, label: t("triage.verdict.fp") },
    { v: "benign", icon: ShieldOff, label: t("triage.verdict.benign") },
  ];
  return (
    <span className="inline-flex gap-0.5">
      {opts.map(({ v, icon: Icon, label }) => (
        <button
          key={v}
          type="button"
          title={label}
          aria-label={label}
          aria-pressed={verdict === v}
          onClick={() => void setVerdict(factId, verdict === v ? null : v)}
          className={clsx(
            "inline-flex h-6 cursor-pointer items-center gap-1 rounded px-1.5 text-[11px] transition-colors",
            verdict === v ? "bg-accent text-accent-fg" : "text-muted hover:bg-raised hover:text-fg",
          )}
        >
          <Icon size={12} aria-hidden />
          {verdict === v && label}
        </button>
      ))}
    </span>
  );
}

function Capability({ c }: { c: CapabilityRow }) {
  const t = useT();
  const loc = c.evidence.find((e) => e.rva != null)?.rva ?? null;
  return (
    <li className={clsx("border-t border-line py-2.5 first:border-t-0", c.verdict === "false_positive" || c.verdict === "benign" ? "opacity-50" : "")}>
      <div className="flex items-center gap-2">
        <SeverityBadge severity={c.severity} label={t(`sev.${c.severity}`)} />
        <span className="font-mono text-[11.5px] text-muted">{c.source_id}</span>
        <span className="truncate text-[12.5px] font-medium">{c.title}</span>
        <span className="ml-auto flex items-center gap-2">
          {loc !== null && (
            <button type="button" onClick={() => void navigate(loc)} className="inline-flex cursor-pointer items-center gap-1 font-mono text-[11.5px] text-accent hover:underline">
              <Crosshair size={12} aria-hidden />
              {hex(loc)}
            </button>
          )}
          <VerdictButtons factId={c.id} verdict={c.verdict} />
        </span>
      </div>
      {c.explain_key && (
        <p className="mt-1.5 max-w-[900px] text-[12px] leading-relaxed text-muted">
          {t(`${c.explain_key}.explain`)} <span className="text-fg/80">{t(`fact.${c.kind}.next`)}</span>
        </p>
      )}
      {c.mitre.length > 0 && <div className="mt-1 font-mono text-[11px] text-faint">{c.mitre.join(" · ")}</div>}
    </li>
  );
}

export function TriageView() {
  const t = useT();
  const { tri, sha, caps } = useStore((s) => ({ tri: s.triage, sha: s.active, caps: s.caps }));
  const [copied, setCopied] = useState(false);
  if (!tri || !sha) {
    return (
      <div className="flex h-full items-center justify-center text-muted">
        <Loader2 size={18} className="animate-spin" aria-hidden />
      </div>
    );
  }
  const running = Object.entries(tri.jobs).filter(([, j]) => j.state === "queued" || j.state === "running").map(([id]) => id);
  const contribs = positiveContributions(tri.score.contributions);
  const review = verdictCounts(tri.capabilities);
  const color = BAND_COLOR[tri.score.band];

  return (
    <div className="h-full overflow-auto p-4">
      <div className="mx-auto grid max-w-[1200px] gap-4">
        <section className="flex flex-wrap items-center gap-6 rounded-lg border border-line bg-panel p-4">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-faint">{t("triage.risk")}</div>
            <div className="flex items-baseline gap-2">
              <span className="text-[36px] font-semibold leading-none" style={{ color }}>{tri.score.score}</span>
              <span className="text-[13px] text-muted">/ 100 · {t(`triage.band.${tri.score.band}`)}</span>
            </div>
            <div className="mt-2 h-1.5 w-56 overflow-hidden rounded-full bg-raised" aria-hidden>
              <div className="h-full" style={{ width: `${tri.score.score}%`, background: color }} />
            </div>
          </div>
          <div className="min-w-[280px] flex-1">
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-faint">{t("triage.why")}</div>
            <ul className="space-y-0.5 text-[12.5px]">
              {contribs.slice(0, 6).map((c) => (
                <li key={c.fact_id} className="flex gap-2">
                  <span className="w-9 shrink-0 text-right font-mono text-muted">+{c.points}</span>
                  <span className="truncate">{c.title}</span>
                </li>
              ))}
              {contribs.length === 0 && <li className="text-muted">{t("triage.nothing")}</li>}
            </ul>
          </div>
          <div className="text-[12px] text-muted">
            {t("triage.reviewed", { n: review.reviewed, total: review.total })}
            {running.length > 0 && (
              <div className="mt-1 flex items-center gap-1.5 text-faint">
                <Loader2 size={12} className="animate-spin" aria-hidden /> {t("triage.running", { jobs: running.join(", ") })}
              </div>
            )}
          </div>
        </section>

        {tri.packer?.packed && (
          <section className="rounded-lg border border-sev-medium/40 bg-panel p-3.5 text-[12.5px]">
            <div className="flex items-center gap-2 font-medium">
              <PackageOpen size={15} className="text-sev-medium" aria-hidden />
              {t("triage.packed", { packer: tri.packer.packer ?? "?" })}
            </div>
            <ul className="mt-1 list-disc pl-6 text-muted">
              {tri.packer.reasons.map((r) => <li key={r}>{r}</li>)}
            </ul>
          </section>
        )}

        <Card title={`${t("triage.capabilities")} (${tri.capabilities.length})`}>
          <ul>{tri.capabilities.map((c) => <Capability key={c.id} c={c} />)}</ul>
        </Card>

        <div className="grid gap-4 xl:grid-cols-2">
          <Card
            title={`${t("triage.iocs")} (${tri.iocs.length})`}
            right={
              tri.iocs.length > 0 && (
                <button
                  type="button"
                  onClick={async () => {
                    await navigator.clipboard.writeText(await api.exportIocs(sha, "csv"));
                    setCopied(true);
                    window.setTimeout(() => setCopied(false), 1200);
                  }}
                  className="inline-flex cursor-pointer items-center gap-1 text-[11.5px] text-muted hover:text-fg"
                >
                  {copied ? <Check size={12} aria-hidden /> : <Copy size={12} aria-hidden />} {t("triage.copy_csv")}
                </button>
              )
            }
          >
            {tri.iocs.length === 0 ? (
              <p className="text-[12.5px] text-muted">{t("triage.no_iocs")}</p>
            ) : (
              <table className="w-full table-fixed text-left text-[12px]">
                <tbody className="selectable">
                  {tri.iocs.map((i) => (
                    <tr key={`${i.type}:${i.value}`} className={clsx("border-t border-line first:border-t-0", i.benign_hint && "opacity-50")}>
                      <td className="w-24 py-1 text-muted">{i.type}</td>
                      <td className="truncate font-mono" title={i.value}>{i.value}</td>
                      <td className="w-40 truncate text-faint">{i.benign_hint}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          <Card title={`${t("triage.top_functions")} (${tri.top_functions.length})`}>
            <ul className="space-y-1.5">
              {tri.top_functions.slice(0, 10).map((f) => (
                <li key={f.start} className="text-[12.5px]">
                  <button type="button" onClick={() => void navigate(f.start, { view: "graph" })} className="cursor-pointer font-mono text-accent hover:underline">
                    {f.name}
                  </button>
                  <span className="ml-2 font-mono text-[11px] text-faint">{f.score}</span>
                  <div className="truncate text-[11.5px] text-muted" title={f.reasons.join("\n")}>{f.reasons.slice(0, 3).join(" · ")}</div>
                </li>
              ))}
            </ul>
          </Card>
        </div>

        {tri.payloads.length > 0 && (
          <Card title={`${t("triage.payloads")} (${tri.payloads.length})`}>
            <ul className="space-y-1.5 text-[12.5px]">
              {tri.payloads.map((p) => (
                <li key={p.sha256} className="flex items-center gap-3">
                  <span className="rounded bg-raised px-1.5 font-mono text-[11px]">{p.kind}</span>
                  <span className="font-mono text-muted">{hex(p.offset)} · {p.size.toLocaleString()} B · {p.where}</span>
                  <span className="ml-auto flex gap-2">
                    <button
                      type="button"
                      onClick={async () => {
                        const child = await api.openPayload(sha, p.sha256);
                        setState((s) => ({ samples: [...s.samples.filter((x) => x.sha256 !== child.sha256), child] }));
                        await selectSample(child.sha256);
                      }}
                      className="inline-flex cursor-pointer items-center gap-1 text-accent hover:underline"
                    >
                      <ExternalLink size={12} aria-hidden /> {t("triage.open_payload")}
                    </button>
                    {caps.native_dialogs && (
                      <button
                        type="button"
                        onClick={async () => {
                          const path = await api.chooseSavePath(`${p.sha256.slice(0, 12)}.zip`);
                          if (path) {
                            await api.exportPayload(sha, p.sha256, path);
                            notify(t("ui.saved", { path }));
                          }
                        }}
                        className="cursor-pointer text-muted hover:text-fg"
                      >
                        {t("triage.export_payload")}
                      </button>
                    )}
                  </span>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[11.5px] text-faint">{t("triage.payload_safety")}</p>
          </Card>
        )}
        {getState().triage?.orphaned_verdicts.length ? (
          <p className="text-[11.5px] text-faint">{t("triage.orphaned", { n: tri.orphaned_verdicts.length })}</p>
        ) : null}
      </div>
    </div>
  );
}
