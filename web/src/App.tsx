import {
  Binary,
  Code2,
  FileCode2,
  FolderOpen,
  Grid3x3,
  LayoutDashboard,
  Loader2,
  Network,
  ShieldAlert,
  TextQuote,
} from "lucide-react";
import { Group, Panel, Separator } from "react-resizable-panels";
import { AnnotateMenu } from "./components/AnnotateMenu";
import { CommandPalette } from "./components/CommandPalette";
import { Dialogs, Toasts } from "./components/Dialogs";
import { DisasmView } from "./components/DisasmView";
import { FindingsView } from "./components/FindingsView";
import { GraphView } from "./components/GraphView";
import { HexView } from "./components/HexView";
import { MitreView } from "./components/MitreView";
import { OverviewView } from "./components/OverviewView";
import { Sidebar } from "./components/Sidebar";
import { StringsView } from "./components/StringsView";
import { TriageView } from "./components/TriageView";
import { TopBar } from "./components/TopBar";
import { XrefPopover } from "./components/XrefPopover";
import { Button, Empty, Tabs } from "./components/ui";
import { hex } from "./lib/format";
import { browseAndOpen, type BottomView, type MainView, setState, useStore, useT } from "./state/store";

function ViewSwitch({ view }: { view: MainView }) {
  switch (view) {
    case "triage":
      return <TriageView />;
    case "overview":
      return <OverviewView />;
    case "disasm":
      return <DisasmView />;
    case "graph":
      return <GraphView />;
    case "hex":
      return <HexView />;
    case "strings":
      return <StringsView />;
  }
}

function useViewTabs() {
  const t = useT();
  return [
    { id: "triage" as const, label: t("ui.triage"), icon: ShieldAlert },
    { id: "overview" as const, label: t("ui.overview"), icon: LayoutDashboard },
    { id: "disasm" as const, label: t("ui.disassembly"), icon: Code2 },
    { id: "graph" as const, label: t("ui.graph"), icon: Network },
    { id: "hex" as const, label: t("ui.hex"), icon: Binary },
    { id: "strings" as const, label: t("ui.strings"), icon: TextQuote },
  ];
}

function Separatorline({ vertical }: { vertical?: boolean }) {
  return (
    <Separator
      className={
        vertical
          ? "h-px bg-line transition-colors hover:bg-accent data-[separator=active]:bg-accent"
          : "w-px bg-line transition-colors hover:bg-accent data-[separator=active]:bg-accent"
      }
    />
  );
}

function Workspace() {
  const t = useT();
  const tabs = useViewTabs();
  const { main, side, bottom, findings, mitre } = useStore((s) => ({
    main: s.main,
    side: s.side,
    bottom: s.bottom,
    findings: s.findings.length,
    mitre: s.mitre.length,
  }));
  return (
    <Group orientation="vertical" className="h-full">
      <Panel minSize={160}>
        <Group orientation="horizontal" className="h-full">
          <Panel minSize={320} className="flex flex-col bg-panel">
            <Tabs<MainView> value={main} onChange={(v) => setState({ main: v })} items={tabs} />
            <div className="min-h-0 flex-1">
              <ViewSwitch view={main} />
            </div>
          </Panel>
          <Separatorline />
          <Panel defaultSize="40" minSize={260} collapsible className="flex flex-col bg-panel">
            <Tabs<MainView>
              value={side}
              onChange={(v) => setState({ side: v })}
              items={tabs.filter((x) => x.id !== "overview" && x.id !== "triage")}
            />
            <div className="min-h-0 flex-1">
              <ViewSwitch view={side} />
            </div>
          </Panel>
        </Group>
      </Panel>
      <Separatorline vertical />
      <Panel defaultSize={260} minSize={120} collapsible className="flex flex-col bg-panel">
        <Tabs<BottomView>
          value={bottom}
          onChange={(v) => setState({ bottom: v })}
          items={[
            { id: "findings", label: t("ui.findings"), icon: ShieldAlert, badge: findings },
            { id: "mitre", label: "MITRE ATT&CK", icon: Grid3x3, badge: mitre },
          ]}
        />
        <div className="min-h-0 flex-1">{bottom === "findings" ? <FindingsView /> : <MitreView />}</div>
      </Panel>
    </Group>
  );
}

function Welcome() {
  const t = useT();
  return (
    <Empty icon={ShieldAlert} title={t("ui.welcome_title")} body={t("ui.welcome_body")}>
      <div className="flex gap-2">
        <Button variant="primary" icon={FolderOpen} onClick={() => void browseAndOpen(false)}>
          {t("ui.open_file")}
        </Button>
        <Button variant="outline" icon={FileCode2} onClick={() => void browseAndOpen(true)}>
          {t("ui.open_raw")}
        </Button>
      </div>
    </Empty>
  );
}

function StatusBar() {
  const t = useT();
  const { ov, nav, discovery, busy, fnName } = useStore((s) => ({
    ov: s.overview,
    nav: s.nav,
    discovery: s.discovery,
    busy: s.busy,
    fnName: s.nav?.fn != null ? s.functions.find((f) => f.start === s.nav?.fn)?.name : undefined,
  }));
  return (
    <footer className="flex h-7 shrink-0 items-center gap-4 border-t border-line bg-panel px-3 font-mono text-[11px] text-faint">
      {busy && (
        <span className="flex items-center gap-1.5 text-muted">
          <Loader2 size={12} className="animate-spin" aria-hidden /> {t("ui.analysing")}
        </span>
      )}
      {ov && <span className="text-muted">{ov.name}</span>}
      {discovery && (
        <span>
          {discovery.state === "running"
            ? t("ui.discovering")
            : discovery.state === "failed"
              ? t("ui.discovery_failed")
              : t("ui.functions_count", { n: discovery.functions })}
        </span>
      )}
      {nav && (
        <span>
          rva {hex(nav.rva)}
          {nav.offset !== null && ` · off ${hex(nav.offset)}`}
          {nav.fn !== null && ` · ${fnName ?? `sub_${nav.fn.toString(16)}`}`}
        </span>
      )}
      <span className="ml-auto">{t("ui.local_only")}</span>
    </footer>
  );
}

export function App() {
  const { ready, active } = useStore((s) => ({ ready: s.ready, active: s.active }));
  if (!ready) {
    return (
      <div className="flex h-full items-center justify-center text-muted">
        <Loader2 className="animate-spin" aria-hidden />
      </div>
    );
  }
  return (
    <div className="flex h-full flex-col">
      <TopBar />
      <div className="min-h-0 flex-1">
        <Group orientation="horizontal" className="h-full">
          <Panel defaultSize={260} minSize={200} maxSize={480} collapsible>
            <Sidebar />
          </Panel>
          <Separatorline />
          <Panel minSize={480}>{active ? <Workspace /> : <Welcome />}</Panel>
        </Group>
      </div>
      <StatusBar />
      <CommandPalette />
      <AnnotateMenu />
      <XrefPopover />
      <Dialogs />
      <Toasts />
    </div>
  );
}
