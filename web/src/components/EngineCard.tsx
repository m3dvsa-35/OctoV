import { Check, Copy, Puzzle } from "lucide-react";
import { useState } from "react";
import type { Extension } from "../api/types";
import { setAutoRun, useT } from "../state/store";

function CopyCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-2 rounded-md border border-line bg-bg px-2 py-1 font-mono text-[11.5px]">
      <span className="selectable truncate">{command}</span>
      <button
        type="button"
        aria-label={`copy ${command}`}
        onClick={async () => {
          await navigator.clipboard.writeText(command);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        }}
        className="ml-auto cursor-pointer text-muted hover:text-fg"
      >
        {copied ? <Check size={12} aria-hidden /> : <Copy size={12} aria-hidden />}
      </button>
    </div>
  );
}

/** What an optional engine adds and the exact commands to enable it (the app never downloads). */
export function EngineCard({ ext }: { ext: Extension }) {
  const t = useT();
  return (
    <section className="rounded-lg border border-dashed border-line bg-panel p-3.5 text-[12.5px]">
      <div className="flex items-center gap-2 font-medium">
        <Puzzle size={14} className="text-muted" aria-hidden />
        <span className="font-mono">{ext.id}</span>
        <span className="text-muted">· {t(ext.reason_key ?? "ext.reason.not_installed")}</span>
        <label className="ml-auto inline-flex cursor-pointer items-center gap-1.5 text-[11.5px] text-muted">
          <input
            type="checkbox"
            checked={ext.auto_run}
            onChange={(e) => void setAutoRun(ext.id, e.target.checked)}
          />
          {t("ext.auto_run")}
        </label>
      </div>
      <p className="mt-1 text-muted">{t(`ext.${ext.id}.adds`)}</p>
      <div className="mt-2 grid gap-1.5">
        {!ext.installed && (
          <>
            <span className="text-[11px] uppercase tracking-wider text-faint">{t("ext.install")}</span>
            <CopyCommand command={ext.install_cmd} />
          </>
        )}
        {ext.setup_cmd && (
          <>
            <span className="text-[11px] uppercase tracking-wider text-faint">{t("ext.setup")}</span>
            <CopyCommand command={ext.setup_cmd} />
          </>
        )}
      </div>
    </section>
  );
}
