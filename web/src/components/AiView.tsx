import clsx from "clsx";
import { Loader2, Send, Sparkles } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../api/client";
import type { AiPreview, AiReport, AiStatus, Severity } from "../api/types";
import { aiError, chips, type Chip } from "../lib/ai";
import { navigate, refreshJobs, setState, useStore, useT } from "../state/store";
import { Button, Empty, SeverityBadge } from "./ui";

const ASSESSMENT_CLASS: Record<AiReport["assessment"], string> = {
  benign: "border-line text-fg",
  suspicious: "border-sev-medium/60 text-sev-medium",
  malicious: "border-sev-high/60 text-sev-high",
};

function ChipRow({ items }: { items: Chip[] }) {
  if (!items.length) return null;
  return (
    <span className="mt-1 flex flex-wrap gap-1">
      {items.map((chip) =>
        chip.kind === "ioc" ? (
          <span key={`i${chip.label}`} className="selectable rounded border border-line px-1.5 font-mono text-[11px] text-muted">
            {chip.label}
          </span>
        ) : (
          <button
            key={`${chip.kind}${chip.label}`}
            type="button"
            onClick={() => (chip.kind === "function" ? void navigate(chip.target, { view: "relations" }) : setState({ bottom: "findings" }))}
            className="cursor-pointer rounded border border-line px-1.5 font-mono text-[11px] text-accent hover:bg-raised"
          >
            {chip.label}
          </button>
        ),
      )}
    </span>
  );
}

function Report({ report, names }: { report: AiReport; names: Map<number, string> }) {
  const t = useT();
  return (
    <div className="grid gap-4">
      <section className="rounded-lg border border-line bg-panel p-4">
        <div className="flex flex-wrap items-center gap-3">
          <span className={clsx("rounded-md border px-2 py-0.5 text-[13px] font-semibold", ASSESSMENT_CLASS[report.assessment])}>
            {t(`ai.assessment.${report.assessment}`)}
          </span>
          <span className="text-[12px] text-muted">
            {t("ai.confidence")}: {t(`ai.conf.${report.confidence}`)}
          </span>
          <span className="ml-auto font-mono text-[11px] text-faint">
            {report.model} · {report.host}
          </span>
        </div>
        <p className="selectable mt-3 text-[13px] leading-relaxed">{report.summary}</p>
        <p className="mt-3 text-[11.5px] text-faint">{t("ai.disclaimer")}</p>
        {report.dropped > 0 && <p className="mt-1 text-[11.5px] text-sev-medium">{t("ai.dropped", { n: report.dropped })}</p>}
      </section>

      {report.story.length > 0 && (
        <section className="rounded-lg border border-line bg-panel p-4">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-faint">{t("ai.story")}</h3>
          <ol className="mt-2 grid gap-2.5">
            {report.story.map((step, i) => (
              <li key={i} className="grid grid-cols-[22px_1fr] text-[12.5px]">
                <span className="font-mono text-faint">{i + 1}.</span>
                <span>
                  <span className="selectable leading-relaxed">{step.text}</span>
                  <ChipRow items={chips(step, names)} />
                </span>
              </li>
            ))}
          </ol>
        </section>
      )}

      {report.points.length > 0 && (
        <section className="rounded-lg border border-line bg-panel p-4">
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-faint">{t("ai.points")}</h3>
          <ul className="mt-2 grid gap-3">
            {report.points.map((point, i) => (
              <li key={i} className="text-[12.5px]">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={point.severity as Severity} label={t(`sev.${point.severity}`)} />
                  <span className="font-medium">{point.title}</span>
                </div>
                <p className="selectable mt-1 leading-relaxed text-muted">{point.why}</p>
                <ChipRow items={chips(point, names)} />
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

export function AiView() {
  const t = useT();
  const { sha, report, job, error, annotations, ready, functions } = useStore((s) => ({
    sha: s.active,
    report: s.aiReport,
    job: s.triage?.jobs.ai?.state ?? null,
    error: s.triage?.jobs.ai?.error ?? null,
    annotations: s.annotationList,
    ready: s.discovery?.state === "done",
    functions: s.functions,
  }));
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [preview, setPreview] = useState<AiPreview | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [again, setAgain] = useState(false);
  const [sending, setSending] = useState(false);
  const names = useMemo(() => new Map(functions.map((f) => [f.start, f.name])), [functions]);

  useEffect(() => {
    void api.aiStatus().then(setStatus, () => setStatus({ configured: false, endpoints: [] }));
  }, []);
  // The preview always shows the evidence as it is now (a rename changes it).
  useEffect(() => {
    if (!sha) return;
    let live = true;
    void api.aiPreview(sha).then(
      (p) => {
        if (!live) return;
        setPreview(p);
        setProblem(null);
      },
      (err: unknown) => live && setProblem(err instanceof ApiError ? err.message : String(err)),
    );
    return () => {
      live = false;
    };
  }, [sha, annotations, ready, report]);

  if (!status) return null;
  if (!status.configured) return <Empty icon={Sparkles} title={t("ai.setup.title")} body={t("ai.setup.body")} />;
  if (problem === "analysis.not_ready") return <Empty icon={Sparkles} title={t("ui.discovering")} />;

  const running = job === "running" || sending;
  const showPreview = !report || again;
  const send = async () => {
    if (!sha || !preview || running) return;
    setSending(true);
    try {
      await api.aiAnalyse(sha, preview.hash, report !== null);
      setAgain(false);
      setProblem(null);
      refreshJobs();
    } catch (err) {
      setProblem(err instanceof ApiError ? err.message : String(err));
      // the evidence changed while the analyst was reading: show the new one to confirm
      void api.aiPreview(sha).then(setPreview, () => undefined);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="h-full overflow-auto p-4" aria-label={t("ui.ai")}>
      <div className="mx-auto grid max-w-[980px] gap-4">
        {report && <Report report={report} names={names} />}

        {(problem || (job === "failed" && error)) && (
          <p role="alert" className="rounded-md border border-sev-high/50 px-3 py-2 text-[12.5px] text-sev-high">
            {aiError(problem ?? error ?? "", t)}
          </p>
        )}

        {running && (
          <p role="status" className="flex items-center gap-2 text-[12.5px] text-muted">
            <Loader2 size={14} className="animate-spin" aria-hidden />
            {t("ai.running", { host: preview?.host ?? "" })}
          </p>
        )}

        {report && !again && !running && (
          <div>
            <Button variant="outline" icon={Sparkles} onClick={() => setAgain(true)}>
              {t("ai.ask_again")}
            </Button>
          </div>
        )}

        {showPreview && preview && !running && (
          <section className="rounded-lg border border-line bg-panel p-4">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-faint">
              {t("ai.preview.title", { n: preview.chars.toLocaleString() })}
            </h3>
            <p className={clsx("mt-2 text-[12.5px] font-medium", preview.local ? "text-fg" : "text-sev-medium")}>
              {t(preview.local ? "ai.dest.local" : "ai.dest.remote", { host: preview.host ?? "", model: preview.model ?? "" })}
            </p>
            <p className="mt-1 text-[11.5px] text-muted">{t("ai.preview.what")}</p>
            {(preview.omitted.code ?? 0) + (preview.omitted.functions ?? 0) + (preview.omitted.findings ?? 0) > 0 && (
              <p className="mt-1 text-[11.5px] text-muted">
                {t("ai.preview.omitted", {
                  code: preview.omitted.code ?? 0,
                  functions: preview.omitted.functions ?? 0,
                  findings: preview.omitted.findings ?? 0,
                })}
              </p>
            )}
            <pre className="selectable mt-3 max-h-[340px] overflow-auto rounded-md border border-line bg-bg p-3 font-mono text-[11.5px] leading-snug">
              {preview.text}
            </pre>
            <div className="mt-3 flex items-center gap-3">
              <Button variant="primary" icon={Send} onClick={() => void send()}>
                {t("ai.send", { host: preview.host ?? "" })}
              </Button>
              {again && (
                <Button variant="ghost" onClick={() => setAgain(false)}>
                  {t("ui.cancel")}
                </Button>
              )}
              <span className="text-[11.5px] text-faint">{t("ai.send_note")}</span>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
