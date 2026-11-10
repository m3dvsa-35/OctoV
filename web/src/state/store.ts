import { useRef, useSyncExternalStore } from "react";
import { api, ApiError } from "../api/client";
import { annotationIndex, type AnnotationIndex } from "../lib/triage";
import { invalidateFunctionCache } from "./hooks";
import type {
  Annotation,
  Capabilities,
  EngineId,
  Extension,
  DiscoveryStatus,
  FindingRow,
  FunctionSummary,
  MitreRow,
  Overview,
  SampleSummary,
  Settings,
  Triage,
  Verdict,
} from "../api/types";

export type MainView =
  | "triage"
  | "overview"
  | "disasm"
  | "graph"
  | "relations"
  | "pseudo_c"
  | "hex"
  | "strings"
  | "search";
export type BottomView = "findings" | "mitre";

export interface Nav {
  rva: number;
  fn: number | null;
  offset: number | null;
}

export interface Toast {
  id: number;
  kind: "error" | "info";
  text: string;
}

/** Where a context menu / popover was opened (viewport coordinates). */
export interface Anchor {
  x: number;
  y: number;
}

export interface State {
  ready: boolean;
  settings: Settings;
  extensions: Extension[];
  strings: Record<string, string>;
  caps: Capabilities;
  samples: SampleSummary[];
  active: string | null;
  overview: Overview | null;
  triage: Triage | null;
  findings: FindingRow[];
  mitre: MitreRow[];
  functions: FunctionSummary[];
  discovery: DiscoveryStatus | null;
  nav: Nav | null;
  history: Nav[];
  future: Nav[];
  main: MainView;
  side: MainView;
  bottom: BottomView;
  busy: boolean;
  annotationList: Annotation[];
  annotations: AnnotationIndex;
  menu: null | (Anchor & { address: number; fn: number | null });
  xref: null | (Anchor & { rva: number; label: string });
  dialog:
    | null
    | { kind: "open"; raw: boolean }
    | { kind: "session"; mode: "new" | "open" }
    | { kind: "export" }
    | { kind: "annotate"; mode: "name" | "comment"; address: number; initial: string };
  palette: boolean;
  toasts: Toast[];
}

let state: State = {
  ready: false,
  settings: { language: "en", theme: "dark", compact: false, extensions_auto_run: { capa: true, floss: true, ghidra: true } },
  extensions: [],
  strings: {},
  caps: { native_dialogs: false },
  samples: [],
  active: null,
  overview: null,
  triage: null,
  findings: [],
  mitre: [],
  functions: [],
  discovery: null,
  nav: null,
  history: [],
  future: [],
  main: "triage",
  side: "graph",
  bottom: "findings",
  busy: false,
  annotationList: [],
  annotations: { comments: {}, bookmarks: {}, names: {} },
  menu: null,
  xref: null,
  dialog: null,
  palette: false,
  toasts: [],
};

const listeners = new Set<() => void>();

export function getState(): State {
  return state;
}

export function setState(patch: Partial<State> | ((s: State) => Partial<State>)): void {
  const next = typeof patch === "function" ? patch(state) : patch;
  state = { ...state, ...next };
  for (const l of listeners) l();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function shallowEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (typeof a !== "object" || typeof b !== "object" || !a || !b) return false;
  const ka = Object.keys(a);
  if (ka.length !== Object.keys(b).length) return false;
  return ka.every((k) => Object.is((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

/** Subscribe to a slice of state; object slices are compared shallowly (stable snapshots). */
export function useStore<T>(selector: (s: State) => T): T {
  const cache = useRef<{ state: State; value: T } | null>(null);
  const getSnapshot = (): T => {
    const prev = cache.current;
    if (prev && prev.state === state) return prev.value;
    const value = selector(state);
    const stable = prev && shallowEqual(prev.value, value) ? prev.value : value;
    cache.current = { state, value: stable };
    return stable;
  };
  return useSyncExternalStore(subscribe, getSnapshot);
}

// -- i18n -------------------------------------------------------------------------

export function t(key: string, vars?: Record<string, string | number>): string {
  let text = state.strings[key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) text = text.replaceAll(`{${k}}`, String(v));
  return text;
}

export function useT(): typeof t {
  useStore((s) => s.strings);
  return t;
}

// -- notifications -------------------------------------------------------------------

let toastId = 0;
export function notify(text: string, kind: Toast["kind"] = "info"): void {
  const id = ++toastId;
  setState((s) => ({ toasts: [...s.toasts, { id, kind, text }] }));
  window.setTimeout(() => setState((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })), 5000);
}

function reportError(err: unknown): void {
  notify(err instanceof ApiError ? err.message : String(err), "error");
}

// -- actions -----------------------------------------------------------------------

export async function boot(): Promise<void> {
  try {
    const [settings, caps] = await Promise.all([api.getSettings(), api.capabilities()]);
    const strings = await api.strings(settings.language);
    document.documentElement.dataset.theme = settings.theme;
    document.documentElement.lang = settings.language;
    const [samples, extensions] = await Promise.all([api.listSamples(), api.extensions()]);
    setState({ settings, caps, strings, samples, extensions, ready: true });
    if (samples[0]) await selectSample(samples[0].sha256);
  } catch (err) {
    setState({ ready: true });
    reportError(err);
  }
}

export async function updateSettings(patch: Partial<Settings>): Promise<void> {
  try {
    const settings = await api.setSettings(patch);
    const strings = patch.language ? await api.strings(settings.language) : state.strings;
    document.documentElement.dataset.theme = settings.theme;
    document.documentElement.lang = settings.language;
    setState({ settings, strings });
  } catch (err) {
    reportError(err);
  }
}

export async function openSample(path: string, raw = false, bits = 64): Promise<void> {
  setState({ busy: true });
  try {
    const summary = await api.openSample(path, raw, bits);
    setState((s) => ({
      samples: [...s.samples.filter((x) => x.sha256 !== summary.sha256), summary],
      dialog: null,
    }));
    await selectSample(summary.sha256);
  } catch (err) {
    reportError(err);
  } finally {
    setState({ busy: false });
  }
}

export async function browseAndOpen(raw: boolean): Promise<void> {
  if (!state.caps.native_dialogs) {
    setState({ dialog: { kind: "open", raw } });
    return;
  }
  const path = await api.chooseFile().catch(reportError);
  if (path) await openSample(path, raw);
}

let pollTimer: number | undefined;

export async function selectSample(sha: string): Promise<void> {
  window.clearTimeout(pollTimer);
  setState({
    active: sha,
    overview: null,
    triage: null,
    findings: [],
    mitre: [],
    functions: [],
    discovery: null,
    nav: null,
    history: [],
    future: [],
    main: "triage",
    annotationList: [],
    annotations: { comments: {}, bookmarks: {}, names: {} },
    menu: null,
    xref: null,
  });
  try {
    const [overview, findings, mitre, triage] = await Promise.all([
      api.overview(sha),
      api.findings(sha),
      api.mitre(sha),
      api.triage(sha),
    ]);
    if (state.active !== sha) return;
    setState({ overview, findings, mitre, triage });
    void loadAnnotations(sha);
    void pollDiscovery(sha);
    void pollJobs(sha);
  } catch (err) {
    reportError(err);
  }
}

async function pollDiscovery(sha: string): Promise<void> {
  try {
    const discovery = await api.discoveryStatus(sha);
    if (state.active !== sha) return;
    setState({ discovery });
    if (discovery.state === "running") {
      pollTimer = window.setTimeout(() => void pollDiscovery(sha), 250);
      return;
    }
    if (discovery.state === "done") {
      const functions = await api.functions(sha);
      if (state.active !== sha) return;
      setState({ functions });
      const entry = functions.find((f) => f.is_entry) ?? functions[0];
      // Background navigation must not pull the analyst away from the tab they are on.
      if (entry && !state.nav) await navigate(entry.start, { record: false, view: state.main });
    }
  } catch (err) {
    reportError(err);
  }
}

/** Re-read the triage report until every background analyzer has finished. */
const FINISHED = new Set(["done", "failed", "unavailable", "idle"]);

/** Poll job states; refresh the report each time a job finishes, not only when all have. */
async function pollJobs(sha: string, seen: Set<string> = new Set()): Promise<void> {
  try {
    const jobs = await api.jobStatus(sha);
    if (state.active !== sha) return;
    const finished = Object.entries(jobs)
      .filter(([, j]) => FINISHED.has(j.state))
      .map(([id, j]) => `${id}:${j.state}:${j.cached}`);
    const changed = finished.some((key) => !seen.has(key));
    const busy = Object.values(jobs).some((j) => j.state === "queued" || j.state === "running");
    if (changed) await refreshAnalysis(sha);
    else setState((s) => (s.triage ? { triage: { ...s.triage, jobs } } : {}));
    if (busy) window.setTimeout(() => void pollJobs(sha, new Set(finished)), 500);
  } catch (err) {
    reportError(err);
  }
}

/** Re-read job states now (a background job can fail after polling has stopped). */
export function refreshJobs(): void {
  if (state.active) void pollJobs(state.active);
}

export async function runExtension(id: EngineId, force: boolean): Promise<void> {
  const sha = state.active;
  if (!sha) return;
  try {
    await api.runExtension(sha, id, force);
    void pollJobs(sha);
  } catch (err) {
    reportError(err);
  }
}

export async function setAutoRun(id: EngineId, value: boolean): Promise<void> {
  await updateSettings({ extensions_auto_run: { ...state.settings.extensions_auto_run, [id]: value } });
  setState({ extensions: await api.extensions().catch(() => state.extensions) });
}

export async function refreshAnalysis(sha: string): Promise<void> {
  const [triage, findings, mitre, samples] = await Promise.all([
    api.triage(sha),
    api.findings(sha),
    api.mitre(sha),
    api.listSamples(),
  ]);
  if (state.active !== sha) return;
  setState({ triage, findings, mitre, samples });
  if (state.discovery?.state === "done") {
    // capa can rename functions (suggested names) after the code views loaded
    const functions = await api.functions(sha);
    if (state.active === sha) setState({ functions });
  }
}

export async function setVerdict(factId: string, verdict: Verdict | null): Promise<void> {
  const sha = state.active;
  if (!sha) return;
  try {
    await api.setVerdict(sha, factId, verdict);
    await refreshAnalysis(sha);
  } catch (err) {
    reportError(err);
  }
}

async function loadAnnotations(sha: string): Promise<void> {
  const list = await api.listAnnotations(sha);
  if (state.active === sha) setState({ annotationList: list, annotations: annotationIndex(list) });
}

/** Replace (or with an empty value, remove) the analyst's name/comment at ``address``. */
async function replaceAnnotation(kind: "name" | "comment", address: number, value: string): Promise<void> {
  const sha = state.active;
  if (!sha) return;
  try {
    for (const a of state.annotationList) {
      if (a.kind === kind && a.address === address) await api.deleteAnnotation(sha, a.id);
    }
    if (value.trim()) await api.annotate(sha, kind, value.trim(), address);
    await loadAnnotations(sha);
    if (kind === "name") {
      invalidateFunctionCache(sha);
      const functions = await api.functions(sha);
      if (state.active === sha) setState({ functions, nav: state.nav ? { ...state.nav } : null });
      await refreshAnalysis(sha);
    }
  } catch (err) {
    reportError(err);
  }
}

export const renameFunction = (start: number, name: string) => replaceAnnotation("name", start, name);
export const setComment = (address: number, text: string) => replaceAnnotation("comment", address, text);

export async function toggleBookmark(address: number): Promise<void> {
  const sha = state.active;
  if (!sha) return;
  try {
    const existing = state.annotations.bookmarks[address];
    if (existing !== undefined) await api.deleteAnnotation(sha, existing);
    else await api.annotate(sha, "bookmark", "", address);
    await loadAnnotations(sha);
  } catch (err) {
    reportError(err);
  }
}

/** Open the rename / comment prompt for ``address`` (rename targets the containing function). */
export function promptAnnotation(mode: "name" | "comment", address: number, fn: number | null): void {
  if (mode === "name") {
    if (fn === null) return;
    const current = state.functions.find((f) => f.start === fn);
    const initial = state.annotations.names[fn] ?? (current && !current.suggested ? current.name : "");
    setState({ menu: null, dialog: { kind: "annotate", mode, address: fn, initial } });
    return;
  }
  setState({ menu: null, dialog: { kind: "annotate", mode, address, initial: state.annotations.comments[address]?.value ?? "" } });
}

/** Keyboard shortcuts shared by the code views: n = rename, ; = comment, b = bookmark, x = xrefs. */
export function annotationKey(e: { key: string; ctrlKey: boolean; altKey: boolean; metaKey: boolean; preventDefault(): void }): void {
  const nav = state.nav;
  if (!nav || e.ctrlKey || e.altKey || e.metaKey || state.dialog) return;
  if (e.key === "n") promptAnnotation("name", nav.rva, nav.fn);
  else if (e.key === ";") promptAnnotation("comment", nav.rva, nav.fn);
  else if (e.key === "b") void toggleBookmark(nav.rva);
  else if (e.key === "x")
    setState({ xref: { x: window.innerWidth / 2 - 160, y: window.innerHeight / 3, rva: nav.rva, label: `0x${nav.rva.toString(16)}` } });
  else return;
  e.preventDefault();
}

export async function closeSample(sha: string): Promise<void> {
  await api.closeSample(sha).catch(reportError);
  const samples = state.samples.filter((s) => s.sha256 !== sha);
  setState({ samples });
  if (state.active === sha) {
    if (samples[0]) await selectSample(samples[0].sha256);
    else setState({ active: null, overview: null, findings: [], mitre: [], functions: [], nav: null });
  }
}

export async function navigate(
  rva: number,
  opts: { record?: boolean; view?: MainView } = {},
): Promise<void> {
  const sha = state.active;
  if (!sha) return;
  try {
    const loc = await api.locate(sha, rva);
    const nav: Nav = { rva, fn: loc.function, offset: loc.offset };
    setState((s) => ({
      nav,
      history: opts.record === false || !s.nav ? s.history : [...s.history.slice(-99), s.nav],
      future: opts.record === false ? s.future : [],
      main: opts.view ?? (s.main === "overview" || s.main === "triage" ? "disasm" : s.main),
    }));
  } catch (err) {
    reportError(err);
  }
}

export function goBack(): void {
  const prev = state.history.at(-1);
  if (!prev) return;
  setState((s) => ({
    nav: prev,
    history: s.history.slice(0, -1),
    future: s.nav ? [s.nav, ...s.future] : s.future,
  }));
}

export function goForward(): void {
  const next = state.future[0];
  if (!next) return;
  setState((s) => ({
    nav: next,
    future: s.future.slice(1),
    history: s.nav ? [...s.history, s.nav] : s.history,
  }));
}

export async function sessionAction(mode: "new" | "open", path?: string): Promise<void> {
  let target = path;
  if (!target && state.caps.native_dialogs) {
    target =
      (mode === "new"
        ? await api.chooseSavePath("case.octov").catch(reportError)
        : await api.chooseFile().catch(reportError)) ?? undefined;
  }
  if (!target) {
    setState({ dialog: { kind: "session", mode } });
    return;
  }
  try {
    if (mode === "new") {
      await api.newSession(target);
      notify(t("ui.session_created", { path: target }));
    } else {
      const opened = await api.openSession(target);
      setState({ samples: await api.listSamples() });
      if (opened[0]) await selectSample(opened[0].sha256);
    }
    setState({ dialog: null });
  } catch (err) {
    reportError(err);
  }
}
