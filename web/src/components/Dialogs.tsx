import clsx from "clsx";
import { AlertTriangle, Check, Copy, Info, Save, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { api } from "../api/client";
import { hex } from "../lib/format";
import {
  getState,
  notify,
  openSample,
  renameFunction,
  sessionAction,
  setComment,
  setState,
  useStore,
  useT,
} from "../state/store";
import { Button, IconButton, Tabs } from "./ui";

function Modal({ title, children, wide }: { title: string; children: ReactNode; wide?: boolean }) {
  const close = () => setState({ dialog: null });
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/45" onMouseDown={close}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(e) => e.stopPropagation()}
        className={clsx("flex max-h-[85vh] flex-col rounded-xl border border-line bg-panel shadow-2xl", wide ? "w-[860px]" : "w-[480px]")}
      >
        <div className="flex h-11 items-center border-b border-line px-4">
          <h2 className="text-[13.5px] font-semibold">{title}</h2>
          <IconButton icon={X} label="Close" className="ml-auto" onClick={close} />
        </div>
        {children}
      </div>
    </div>
  );
}

function PathDialog({ title, hint, action, extra }: {
  title: string;
  hint: string;
  action: (path: string) => void;
  extra?: ReactNode;
}) {
  const t = useT();
  const [path, setPath] = useState("");
  return (
    <Modal title={title}>
      <form
        className="flex flex-col gap-3 p-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (path.trim()) action(path.trim().replace(/^"|"$/g, ""));
        }}
      >
        <label className="flex flex-col gap-1.5">
          <span className="text-[12px] text-muted">{hint}</span>
          <input
            autoFocus
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="C:\\samples\\sample.exe"
            className="h-8 rounded-md border border-line bg-bg px-2.5 font-mono text-[12.5px] outline-none focus:border-accent/60"
          />
        </label>
        {extra}
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => setState({ dialog: null })}>
            {t("ui.cancel")}
          </Button>
          <Button variant="primary" type="submit" disabled={!path.trim()}>
            {t("ui.open")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function OpenDialog({ raw }: { raw: boolean }) {
  const t = useT();
  const [bits, setBits] = useState(64);
  return (
    <PathDialog
      title={raw ? t("ui.open_raw") : t("ui.open_file")}
      hint={t("ui.path_hint")}
      action={(p) => void openSample(p, raw, bits)}
      extra={
        raw && (
          <div className="flex items-center gap-3 text-[12.5px]">
            <span className="text-muted">{t("ui.architecture")}</span>
            {[64, 32].map((b) => (
              <label key={b} className="flex cursor-pointer items-center gap-1.5">
                <input type="radio" checked={bits === b} onChange={() => setBits(b)} className="accent-[var(--accent)]" />
                x{b === 64 ? "64" : "86"}
              </label>
            ))}
          </div>
        )
      }
    />
  );
}

function ExportDialog() {
  const t = useT();
  const sha = useStore((s) => s.active);
  const [tab, setTab] = useState<"yara" | "sigma">("yara");
  const [text, setText] = useState<{ yara: string; sigma: string | null } | null>(null);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!sha) return;
    void Promise.all([api.exportYara(sha), api.exportSigma(sha)]).then(([yara, sigma]) => setText({ yara, sigma }));
  }, [sha]);
  const body = text ? (tab === "yara" ? text.yara : text.sigma) : null;
  const name = getState().overview?.name.replace(/\.[^.]+$/, "") ?? "sample";

  return (
    <Modal title={t("ui.export")} wide>
      <Tabs<"yara" | "sigma">
        value={tab}
        onChange={setTab}
        items={[
          { id: "yara", label: "YARA" },
          { id: "sigma", label: "Sigma" },
        ]}
        right={
          body && (
            <>
              <Button
                icon={copied ? Check : Copy}
                onClick={() => {
                  void navigator.clipboard.writeText(body);
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1200);
                }}
              >
                {copied ? t("ui.copied") : t("ui.copy")}
              </Button>
              {getState().caps.native_dialogs && (
                <Button
                  icon={Save}
                  onClick={async () => {
                    const path = await api.chooseSavePath(`${name}.${tab === "yara" ? "yar" : "yml"}`);
                    if (path) {
                      await api.saveText(path, body);
                      notify(t("ui.saved", { path }));
                    }
                  }}
                >
                  {t("ui.save")}
                </Button>
              )}
            </>
          )
        }
      />
      <div className="min-h-[320px] overflow-auto p-4">
        {body === null && text ? (
          <p className="text-[12.5px] text-muted">{t("ui.sigma_needs_pe")}</p>
        ) : (
          <pre className="selectable whitespace-pre font-mono text-[12px] leading-5 text-fg">{body}</pre>
        )}
      </div>
    </Modal>
  );
}

function AnnotateDialog({ mode, address, initial }: { mode: "name" | "comment"; address: number; initial: string }) {
  const t = useT();
  const [value, setValue] = useState(initial);
  const valid = mode === "comment" || value.trim() === "" || /^[A-Za-z_$?@][\w$?@.:<>~-]{0,127}$/.test(value.trim());
  return (
    <Modal title={`${mode === "name" ? t("annotate.rename") : t("annotate.comment")} · ${hex(address)}`}>
      <form
        className="flex flex-col gap-3 p-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (!valid) return;
          setState({ dialog: null });
          void (mode === "name" ? renameFunction(address, value) : setComment(address, value));
        }}
      >
        <label className="flex flex-col gap-1.5">
          <span className="text-[12px] text-muted">{mode === "name" ? t("annotate.rename_hint") : t("annotate.comment_hint")}</span>
          <input
            autoFocus
            value={value}
            onChange={(e) => setValue(e.target.value)}
            aria-invalid={!valid}
            className="h-8 rounded-md border border-line bg-bg px-2.5 font-mono text-[12.5px] outline-none focus:border-accent/60 aria-[invalid=true]:border-sev-high"
          />
          {!valid && <span className="text-[11.5px] text-sev-high">{t("annotate.invalid_name")}</span>}
        </label>
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => setState({ dialog: null })}>
            {t("ui.cancel")}
          </Button>
          <Button variant="primary" type="submit" disabled={!valid}>
            {t("annotate.save")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export function Dialogs() {
  const t = useT();
  const dialog = useStore((s) => s.dialog);
  if (!dialog) return null;
  if (dialog.kind === "open") return <OpenDialog raw={dialog.raw} />;
  if (dialog.kind === "export") return <ExportDialog />;
  if (dialog.kind === "annotate") return <AnnotateDialog key={`${dialog.mode}:${dialog.address}`} {...dialog} />;
  return (
    <PathDialog
      title={dialog.mode === "new" ? t("ui.new_session") : t("ui.open_session")}
      hint={t("ui.session_hint")}
      action={(p) => void sessionAction(dialog.mode, p)}
    />
  );
}

export function Toasts() {
  const toasts = useStore((s) => s.toasts);
  return (
    <div className="pointer-events-none fixed bottom-9 right-4 z-[60] flex flex-col gap-2" aria-live="polite">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={clsx(
            "pointer-events-auto flex max-w-[420px] items-start gap-2 rounded-lg border bg-panel px-3 py-2.5 text-[12.5px] shadow-xl",
            toast.kind === "error" ? "border-sev-high/40" : "border-line",
          )}
        >
          {toast.kind === "error" ? (
            <AlertTriangle size={15} className="mt-0.5 shrink-0 text-sev-high" aria-hidden />
          ) : (
            <Info size={15} className="mt-0.5 shrink-0 text-accent" aria-hidden />
          )}
          <span className="selectable break-words">{toast.text}</span>
        </div>
      ))}
    </div>
  );
}
