import { Command } from "cmdk";
import { CornerDownLeft, FileOutput, Hash, Network, SquareFunction } from "lucide-react";
import { useEffect, useState } from "react";
import { parseAddress } from "../lib/format";
import { getState, navigate, setState, useStore, useT } from "../state/store";

export function CommandPalette() {
  const t = useT();
  const { open, functions, findings } = useStore((s) => ({
    open: s.palette,
    functions: s.functions,
    findings: s.findings,
  }));
  const [query, setQuery] = useState("");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (getState().active) setState((s) => ({ palette: !s.palette }));
      }
      if (e.key === "g" && !e.ctrlKey && !(e.target instanceof HTMLInputElement) && getState().active) {
        e.preventDefault();
        setState({ palette: true });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (!open) return null;
  const close = () => {
    setState({ palette: false });
    setQuery("");
  };
  const address = parseAddress(query);

  return (
    <div className="fixed inset-0 z-50 flex justify-center bg-black/40 pt-[12vh]" onMouseDown={close}>
      <Command
        label={t("ui.command_palette")}
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={(e) => e.key === "Escape" && close()}
        className="h-fit w-[560px] overflow-hidden rounded-xl border border-line bg-panel shadow-2xl"
        shouldFilter
      >
        <Command.Input
          autoFocus
          value={query}
          onValueChange={setQuery}
          placeholder={t("ui.palette_placeholder")}
          className="h-11 w-full border-b border-line bg-transparent px-4 text-[13.5px] outline-none placeholder:text-faint"
        />
        <Command.List className="max-h-[380px] overflow-auto p-1.5">
          <Command.Empty className="px-3 py-6 text-center text-[12.5px] text-muted">
            {t("ui.no_results")}
          </Command.Empty>
          {address !== null && (
            <Command.Group heading={t("ui.goto")} className="text-[11px] text-faint">
              <Item
                value={`goto ${query}`}
                icon={Hash}
                onSelect={() => {
                  close();
                  void navigate(address);
                }}
              >
                {t("ui.goto_address", { addr: `0x${address.toString(16)}` })}
              </Item>
            </Command.Group>
          )}
          <Command.Group heading={t("ui.actions")}>
            <Item value="graph view" icon={Network} onSelect={() => { close(); setState({ main: "graph" }); }}>
              {t("ui.show_graph")}
            </Item>
            <Item value="export yara sigma" icon={FileOutput} onSelect={() => { close(); setState({ dialog: { kind: "export" } }); }}>
              {t("ui.export")}
            </Item>
          </Command.Group>
          {findings.some((f) => f.rva !== null) && (
            <Command.Group heading={t("ui.findings")}>
              {findings
                .filter((f) => f.rva !== null)
                .map((f) => (
                  <Item
                    key={f.id}
                    value={`${f.id} ${f.name}`}
                    icon={CornerDownLeft}
                    onSelect={() => {
                      close();
                      void navigate(f.rva as number);
                    }}
                  >
                    <span className="font-mono text-muted">{f.id}</span> {f.name}
                  </Item>
                ))}
            </Command.Group>
          )}
          <Command.Group heading={t("ui.functions")}>
            {functions.slice(0, 2000).map((fn) => (
              <Item
                key={fn.start}
                value={`${fn.name} ${fn.start.toString(16)}`}
                icon={SquareFunction}
                onSelect={() => {
                  close();
                  void navigate(fn.start);
                }}
              >
                <span className="font-mono">{fn.name}</span>
              </Item>
            ))}
          </Command.Group>
        </Command.List>
      </Command>
    </div>
  );
}

function Item({
  value,
  icon: Icon,
  onSelect,
  children,
}: {
  value: string;
  icon: typeof Hash;
  onSelect: () => void;
  children: React.ReactNode;
}) {
  return (
    <Command.Item
      value={value}
      onSelect={onSelect}
      className="flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[12.5px] text-fg data-[selected=true]:bg-raised"
    >
      <Icon size={14} className="text-muted" aria-hidden />
      {children}
    </Command.Item>
  );
}
