import { Check, Copy, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { useState, type ReactNode } from "react";
import type { Overview } from "../api/types";
import { formatBytes, hex } from "../lib/format";
import { navigate, useStore, useT } from "../state/store";
import { MemoryMap } from "./MemoryMap";
import { SeverityBadge } from "./ui";

function CopyValue({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(value);
        setDone(true);
        window.setTimeout(() => setDone(false), 1200);
      }}
      className="group inline-flex max-w-full cursor-pointer items-center gap-1.5 font-mono text-[12px] text-fg"
    >
      <span className="selectable truncate">{value}</span>
      {done ? (
        <Check size={12} className="shrink-0 text-edge-true" aria-hidden />
      ) : (
        <Copy size={12} className="shrink-0 text-faint opacity-0 group-hover:opacity-100" aria-hidden />
      )}
    </button>
  );
}

function Card({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-line bg-panel ${className ?? ""}`}>
      <h3 className="border-b border-line px-3.5 py-2 text-[11px] font-semibold uppercase tracking-wider text-faint">
        {title}
      </h3>
      <div className="p-3.5">{children}</div>
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[110px_1fr] items-center gap-3 py-1">
      <dt className="text-[12px] text-muted">{label}</dt>
      <dd className="min-w-0 text-[12.5px]">{children}</dd>
    </div>
  );
}

function entropyColor(e: number): string {
  if (e >= 7.2) return "bg-sev-high";
  if (e >= 6.5) return "bg-sev-medium";
  return "bg-accent";
}

export function OverviewView() {
  const t = useT();
  const { ov, findings } = useStore((s) => ({ ov: s.overview, findings: s.findings }));
  if (!ov) return null;
  const top = findings.slice(0, 6);
  return (
    <div className="h-full overflow-auto p-4">
      <div className="mx-auto grid max-w-[1200px] grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title={t("ui.identity")}>
          <dl>
            <Field label={t("ui.file")}>
              <span className="selectable font-medium">{ov.name}</span>
            </Field>
            <Field label={t("ui.size")}>{formatBytes(ov.size)}</Field>
            <Field label="SHA-256">
              <CopyValue value={ov.hashes.sha256} />
            </Field>
            <Field label="SHA-1">
              <CopyValue value={ov.hashes.sha1} />
            </Field>
            <Field label="MD5">
              <CopyValue value={ov.hashes.md5} />
            </Field>
            {ov.hashes.imphash && (
              <Field label="Imphash">
                <CopyValue value={ov.hashes.imphash} />
              </Field>
            )}
          </dl>
        </Card>

        <Card title={t("ui.binary")}>
          <dl>
            {ov.format === "pe" ? (
              <PeFields ov={ov} />
            ) : (
              <>
                <Field label={t("ui.format")}>{t("ui.raw_blob", { bits: ov.bits ?? 64 })}</Field>
                <Field label={t("ui.entropy")}>{ov.entropy.toFixed(3)}</Field>
              </>
            )}
          </dl>
        </Card>

        {top.length > 0 && (
          <Card title={t("ui.top_findings")} className="xl:col-span-2">
            <ul className="divide-y divide-line">
              {top.map((f) => (
                <li key={f.id} className="flex items-center gap-3 py-2">
                  <SeverityBadge severity={f.severity} label={t(`sev.${f.severity}`)} />
                  <span className="font-mono text-[11.5px] text-muted">{f.source_id}</span>
                  <span className="truncate text-[12.5px]">{f.kind === "rule" ? f.name : f.description}</span>
                  {f.rva !== null && (
                    <button
                      type="button"
                      onClick={() => void navigate(f.rva as number)}
                      className="ml-auto cursor-pointer font-mono text-[11.5px] text-accent hover:underline"
                    >
                      {hex(f.rva)}
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </Card>
        )}

        <Card title={t("map.title")} className="xl:col-span-2">
          <MemoryMap />
        </Card>

        {ov.sections && (
          <Card title={t("ui.sections")} className="xl:col-span-2">
            <table className="w-full text-left text-[12px]">
              <thead className="text-[11px] uppercase tracking-wide text-faint">
                <tr>
                  {["name", "VA", "VSize", "Raw", "perm", "entropy"].map((h) => (
                    <th key={h} className="pb-2 font-medium">
                      {h === "name" ? t("ui.name") : h === "perm" ? t("ui.perm") : h === "entropy" ? t("ui.entropy") : h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="font-mono">
                {ov.sections.map((s) => (
                  <tr key={`${s.name}-${s.va}`} className="border-t border-line">
                    <td className="py-1.5 font-sans font-medium">{s.name}</td>
                    <td className="text-muted">{hex(s.va)}</td>
                    <td className="text-muted">{hex(s.vsize)}</td>
                    <td className="text-muted">{hex(s.raw_size)}</td>
                    <td className={s.perm.includes("W") && s.perm.includes("X") ? "text-sev-high" : ""}>
                      {s.perm}
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-24 overflow-hidden rounded-full bg-raised" aria-hidden>
                          <div className={`h-full ${entropyColor(s.entropy)}`} style={{ width: `${(s.entropy / 8) * 100}%` }} />
                        </div>
                        <span>{s.entropy.toFixed(2)}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}

        {ov.imports && Object.keys(ov.imports).length > 0 && (
          <Card title={`${t("ui.imports")} (${Object.values(ov.imports).flat().length})`} className="xl:col-span-2">
            <div className="grid gap-3 md:grid-cols-2">
              {Object.entries(ov.imports).map(([dll, funcs]) => (
                <div key={dll}>
                  <div className="mb-1 font-mono text-[11.5px] font-semibold text-muted">{dll}</div>
                  <div className="selectable flex flex-wrap gap-1">
                    {funcs.map((f) => (
                      <span key={f} className="rounded bg-raised px-1.5 py-0.5 font-mono text-[11px]">
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}

function PeFields({ ov }: { ov: Overview }) {
  const t = useT();
  const sig = ov.signature;
  const SigIcon = !sig?.present ? ShieldQuestion : sig.verified ? ShieldCheck : ShieldAlert;
  return (
    <>
      <Field label={t("ui.format")}>
        {ov.machine} · {ov.is_64bit ? "PE32+" : "PE32"} · {ov.is_dll ? "DLL" : "EXE"} · {ov.subsystem}
      </Field>
      <Field label={t("ui.entry_point")}>
        <button
          type="button"
          onClick={() => ov.entry_point !== undefined && void navigate(ov.entry_point)}
          className="cursor-pointer font-mono text-[12px] text-accent hover:underline"
        >
          {hex(ov.entry_point ?? 0)}
        </button>
        <span className="ml-2 font-mono text-[11.5px] text-faint">
          {t("ui.image_base")} {hex(ov.image_base ?? 0)}
        </span>
      </Field>
      <Field label={t("ui.compiled")}>
        <span className="font-mono text-[12px]">{ov.compile_time?.replace("T", " ").replace("+00:00", " UTC")}</span>
      </Field>
      <Field label={t("ui.entropy")}>{ov.entropy.toFixed(3)}</Field>
      <Field label={t("ui.signature")}>
        <span className="inline-flex items-center gap-1.5">
          <SigIcon size={14} aria-hidden className={sig?.verified ? "text-edge-true" : "text-muted"} />
          {!sig?.present ? t("ui.unsigned") : sig.verified ? t("ui.signed_valid") : t("ui.signed_unverified")}
        </span>
      </Field>
      <Field label={t("ui.overlay")}>{formatBytes(ov.overlay_size ?? 0)}</Field>
    </>
  );
}
