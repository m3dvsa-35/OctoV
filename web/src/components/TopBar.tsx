import {
  ArrowLeft,
  ArrowRight,
  Binary,
  FileCode2,
  FolderOpen,
  Moon,
  Save,
  Search,
  ShieldCheck,
  Sun,
  FileOutput,
  Rows3,
} from "lucide-react";
import {
  browseAndOpen,
  goBack,
  goForward,
  sessionAction,
  setState,
  updateSettings,
  useStore,
  useT,
} from "../state/store";
import clsx from "clsx";
import { Button, IconButton, Kbd, Segmented } from "./ui";

export function TopBar() {
  const t = useT();
  const { settings, history, future, active, busy } = useStore((s) => ({
    settings: s.settings,
    history: s.history.length,
    future: s.future.length,
    active: s.active,
    busy: s.busy,
  }));
  return (
    <header className="flex h-11 shrink-0 items-center gap-2 border-b border-line bg-panel px-3">
      <div className="flex items-center gap-2 pr-2">
        <div className="flex size-6 items-center justify-center rounded-md bg-accent text-accent-fg">
          <Binary size={14} strokeWidth={2.25} aria-hidden />
        </div>
        <span className="text-[13.5px] font-semibold tracking-tight">OctoV</span>
      </div>
      <div className="h-5 w-px bg-line" />
      <Button icon={FolderOpen} onClick={() => void browseAndOpen(false)} disabled={busy}>
        {t("ui.open_file")}
      </Button>
      <Button icon={FileCode2} onClick={() => void browseAndOpen(true)} disabled={busy}>
        {t("ui.open_raw")}
      </Button>
      <Button icon={Save} onClick={() => void sessionAction("new")}>
        {t("ui.new_session")}
      </Button>
      <Button icon={FolderOpen} onClick={() => void sessionAction("open")}>
        {t("ui.open_session")}
      </Button>
      <div className="h-5 w-px bg-line" />
      <IconButton icon={ArrowLeft} label={t("ui.back")} onClick={goBack} disabled={!history} />
      <IconButton icon={ArrowRight} label={t("ui.forward")} onClick={goForward} disabled={!future} />

      <button
        type="button"
        onClick={() => setState({ palette: true })}
        disabled={!active}
        className="mx-auto flex h-7 w-[360px] max-w-[40vw] cursor-pointer items-center gap-2 rounded-md border border-line bg-bg px-2.5 text-[12.5px] text-faint transition-colors hover:border-muted/40 disabled:cursor-default disabled:opacity-50"
      >
        <Search size={14} aria-hidden />
        <span className="truncate">{t("ui.command_palette")}</span>
        <span className="ml-auto flex gap-0.5">
          <Kbd>Ctrl</Kbd>
          <Kbd>K</Kbd>
        </span>
      </button>

      <Button
        icon={FileOutput}
        variant="outline"
        disabled={!active}
        onClick={() => setState({ dialog: { kind: "export" } })}
      >
        {t("ui.export")}
      </Button>
      <button
        type="button"
        aria-pressed={settings.compact}
        title={t("ui.compact_hint")}
        onClick={() => void updateSettings({ compact: !settings.compact })}
        className={clsx(
          "inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-md border px-2 text-[12px] transition-colors",
          settings.compact ? "border-accent bg-accent/15 text-fg" : "border-line text-muted hover:text-fg",
        )}
      >
        <Rows3 size={13} aria-hidden />
        {t("ui.compact")}
      </button>
      <Segmented<"en" | "az">
        label={t("ui.language")}
        value={settings.language}
        onChange={(language) => void updateSettings({ language })}
        options={[
          { id: "en", label: "EN" },
          { id: "az", label: "AZ" },
        ]}
      />
      <Segmented<"dark" | "light">
        label={t("ui.display_mode")}
        value={settings.theme}
        onChange={(theme) => void updateSettings({ theme })}
        options={[
          { id: "dark", label: t("ui.theme_night"), icon: Moon },
          { id: "light", label: t("ui.theme_normal"), icon: Sun },
        ]}
      />
      <span
        className="ml-1 inline-flex items-center gap-1 text-[11.5px] text-faint"
        title={t("ui.local_only")}
      >
        <ShieldCheck size={14} aria-hidden />
        {t("ui.local")}
      </span>
    </header>
  );
}
