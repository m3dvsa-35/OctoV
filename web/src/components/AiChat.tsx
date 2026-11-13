import clsx from "clsx";
import { Eye, Loader2, Send, Trash2 } from "lucide-react";
import { useState } from "react";
import { api, ApiError } from "../api/client";
import type { AiChatPreview } from "../api/types";
import { aiError, chips, type Chip } from "../lib/ai";
import { loadAiReport, navigate, refreshJobs, setState, useStore, useT } from "../state/store";
import { Button } from "./ui";

function Chips({ items }: { items: Chip[] }) {
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

/** Follow-up questions: every question is previewed as the whole message and confirmed. */
export function AiChat({ names }: { names: Map<number, string> }) {
  const t = useT();
  const { sha, turns, job, jobError, fn, fnName } = useStore((s) => ({
    sha: s.active,
    turns: s.aiChat,
    job: s.triage?.jobs.ai_chat?.state ?? null,
    jobError: s.triage?.jobs.ai_chat?.error ?? null,
    fn: s.nav?.fn ?? null,
    fnName: s.nav?.fn != null ? s.functions.find((f) => f.start === s.nav?.fn)?.name : undefined,
  }));
  const [question, setQuestion] = useState("");
  const [useFocus, setUseFocus] = useState(false);
  const [preview, setPreview] = useState<(AiChatPreview & { question: string; focus: number | null }) | null>(null);
  const [choice, setChoice] = useState(0);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [clearing, setClearing] = useState(false);

  const focus = useFocus && fn !== null ? fn : null;
  const running = job === "running" || busy;
  const target = preview?.endpoints[choice] ?? preview?.endpoints[0] ?? null;
  const fail = (err: unknown) => setProblem(err instanceof ApiError ? err.message : String(err));

  const look = async () => {
    if (!sha || !question.trim() || running) return;
    setBusy(true);
    try {
      const p = await api.aiChatPreview(sha, question, focus);
      setPreview({ ...p, question, focus });
      setProblem(null);
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };
  const send = async () => {
    if (!sha || !preview || running) return;
    setBusy(true);
    try {
      await api.aiAsk(sha, preview.question, preview.hash, preview.focus, target ? choice : 0);
      setPreview(null);
      setQuestion("");
      setProblem(null);
      refreshJobs();
    } catch (err) {
      fail(err);
      setPreview(null); // what was shown is no longer what would be sent: look again
    } finally {
      setBusy(false);
    }
  };
  const clear = async () => {
    if (!sha) return;
    await api.aiChatClear(sha).catch(fail);
    setClearing(false);
    void loadAiReport(sha);
  };

  return (
    <section className="min-w-0 rounded-lg border border-line bg-panel p-4" aria-label={t("ai.chat.title")}>
      <div className="flex items-center gap-3">
        <h3 className="text-[11px] font-semibold uppercase tracking-wider text-faint">{t("ai.chat.title")}</h3>
        {turns.length > 0 &&
          (clearing ? (
            <span className="ml-auto flex items-center gap-2 text-[11.5px]">
              {t("ai.chat.clear_confirm")}
              <Button variant="outline" onClick={() => void clear()}>
                {t("ai.chat.clear")}
              </Button>
              <Button variant="ghost" onClick={() => setClearing(false)}>
                {t("ui.cancel")}
              </Button>
            </span>
          ) : (
            <Button variant="ghost" icon={Trash2} className="ml-auto" onClick={() => setClearing(true)}>
              {t("ai.chat.clear")}
            </Button>
          ))}
      </div>

      {turns.length === 0 && <p className="mt-2 text-[12.5px] text-muted">{t("ai.chat.empty")}</p>}
      <ol className="mt-2 grid gap-3">
        {turns.map((turn, i) => (
          <li key={`${turn.created}-${i}`} className="text-[12.5px]">
            <p className="selectable font-medium">
              <span className="mr-1.5 text-faint">{t("ai.chat.you")}:</span>
              {turn.question}
            </p>
            <p className="selectable mt-1 whitespace-pre-wrap leading-relaxed text-muted">
              <span className="mr-1.5 text-faint">{t("ai.mark")}:</span>
              {turn.answer}
            </p>
            <Chips items={chips(turn, names)} />
            <p className="mt-1 font-mono text-[10.5px] text-faint">
              {turn.model} · {turn.host}
              {turn.dropped > 0 && <span className="ml-2 text-sev-medium">{t("ai.dropped", { n: turn.dropped })}</span>}
            </p>
          </li>
        ))}
      </ol>

      {(problem || (job === "failed" && jobError)) && (
        <p role="alert" className="mt-3 rounded-md border border-sev-high/50 px-3 py-2 text-[12.5px] text-sev-high">
          {aiError(problem ?? jobError ?? "", t)}
        </p>
      )}
      {job === "running" && (
        <p role="status" className="mt-3 flex items-center gap-2 text-[12.5px] text-muted">
          <Loader2 size={14} className="animate-spin" aria-hidden />
          {t("ai.chat.running")}
        </p>
      )}

      {!preview && (
        <form
          className="mt-3 grid gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void look();
          }}
        >
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            maxLength={1000}
            rows={2}
            placeholder={t("ai.chat.placeholder")}
            aria-label={t("ai.chat.placeholder")}
            className="w-full resize-y rounded-md border border-line bg-bg px-2.5 py-1.5 text-[12.5px] text-fg outline-none placeholder:text-faint focus:border-accent/60"
          />
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="outline" icon={Eye} type="submit" disabled={running || !question.trim()}>
              {t("ai.chat.preview")}
            </Button>
            {fn !== null && (
              <label className="inline-flex cursor-pointer items-center gap-1.5 text-[12px] text-muted">
                <input type="checkbox" checked={useFocus} onChange={(e) => setUseFocus(e.target.checked)} />
                {t("ai.chat.focus", { name: fnName ?? `sub_${fn.toString(16)}` })}
              </label>
            )}
            <span className="text-[11.5px] text-faint">{t("ai.send_note")}</span>
          </div>
        </form>
      )}

      {preview && (
        <div className="mt-3">
          <h4 className="text-[11px] font-semibold uppercase tracking-wider text-faint">
            {t("ai.chat.preview_title", { n: preview.chars.toLocaleString() })}
          </h4>
          {preview.endpoints.length > 1 && (
            <div className="mt-2 flex flex-wrap items-center gap-3 text-[12px]" role="radiogroup" aria-label={t("ai.destination")}>
              <span className="text-muted">{t("ai.destination")}</span>
              {preview.endpoints.map((e, i) => (
                <label key={`${e.host}:${e.model}`} className="inline-flex cursor-pointer items-center gap-1.5">
                  <input type="radio" name="ai-chat-destination" checked={choice === i} onChange={() => setChoice(i)} />
                  <span className="font-mono">
                    {e.host} · {e.model}
                  </span>
                </label>
              ))}
            </div>
          )}
          <p className={clsx("mt-2 text-[12.5px] font-medium", target?.local ? "text-fg" : "text-sev-medium")}>
            {target
              ? t(target.local ? "ai.dest.local" : "ai.dest.remote", { host: target.host, model: target.model })
              : t("ai.error.no_endpoint")}
          </p>
          <pre className="selectable mt-2 max-h-[300px] overflow-auto rounded-md border border-line bg-bg p-3 font-mono text-[11.5px] leading-snug">
            {preview.text}
          </pre>
          <div className="mt-3 flex items-center gap-3">
            <Button variant="primary" icon={Send} onClick={() => void send()} disabled={running || !target}>
              {t("ai.send", { host: target?.host ?? "" })}
            </Button>
            <Button variant="ghost" onClick={() => setPreview(null)}>
              {t("ui.cancel")}
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}
