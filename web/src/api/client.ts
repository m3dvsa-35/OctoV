import type {
  AiPreview,
  AiReport,
  AiStatus,
  Annotation,
  AnnotationKind,
  EngineId,
  Extension,
  ByteChunk,
  Capabilities,
  Decompiled,
  DiscoveryStatus,
  FindingRow,
  FunctionData,
  FunctionSummary,
  InstructionData,
  Location,
  MemoryMapData,
  MitreRow,
  Overview,
  Relations,
  SampleSummary,
  SearchKind,
  SearchResult,
  Settings,
  StringsPage,
  Symbols,
  Triage,
  Verdict,
  XrefRow,
} from "./types";

/**
 * Transport to the Python core.
 *
 * Desktop: pywebview injects `window.pywebview.api` (in-process bridge, no network).
 * Development: the loopback dev server answers POST /rpc and requires the per-run
 * token, passed once as `?token=` and kept in sessionStorage.
 */
type Bridge = Record<string, (...args: unknown[]) => Promise<unknown>>;

declare global {
  interface Window {
    pywebview?: { api: Bridge };
  }
}

export class ApiError extends Error {}

const TOKEN_KEY = "octov.token";

function devToken(): string {
  const fromUrl = new URLSearchParams(window.location.search).get("token");
  if (fromUrl) {
    sessionStorage.setItem(TOKEN_KEY, fromUrl);
    window.history.replaceState(null, "", window.location.pathname);
    return fromUrl;
  }
  return sessionStorage.getItem(TOKEN_KEY) ?? "";
}

let bridgeReady: Promise<Bridge | null> | null = null;

function bridge(): Promise<Bridge | null> {
  bridgeReady ??= new Promise((resolve) => {
    if (window.pywebview?.api) return resolve(window.pywebview.api);
    // Not inside the desktop shell -> dev server mode (unless the bridge shows up quickly).
    const timer = window.setTimeout(() => resolve(null), 400);
    window.addEventListener("pywebviewready", () => {
      window.clearTimeout(timer);
      resolve(window.pywebview?.api ?? null);
    });
  });
  return bridgeReady;
}

async function call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  const api = await bridge();
  if (api) {
    const fn = api[method];
    if (!fn) throw new ApiError(`unknown method ${method}`);
    try {
      // Parameters are always declared in the Python signature's order.
      return (await fn(...Object.values(params))) as T;
    } catch (err) {
      const message = (err as { message?: string })?.message ?? String(err);
      throw new ApiError(message.replace(/^ApiError:\s*/, ""));
    }
  }
  const response = await fetch("rpc", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-OctoV-Token": devToken() },
    body: JSON.stringify({ method, params }),
  });
  const payload = (await response.json().catch(() => ({}))) as { result?: T; error?: string };
  if (!response.ok || payload.error !== undefined) {
    throw new ApiError(payload.error ?? `HTTP ${response.status}`);
  }
  return payload.result as T;
}

export const api = {
  capabilities: () => call<Capabilities>("capabilities"),
  getSettings: () => call<Settings>("get_settings"),
  setSettings: (settings: Partial<Settings>) => call<Settings>("set_settings", { settings }),
  strings: (lang: string) => call<Record<string, string>>("strings", { lang }),
  chooseFile: () => call<string | null>("choose_file"),
  chooseSavePath: (suggested: string) => call<string | null>("choose_save_path", { suggested }),
  saveText: (path: string, text: string) => call<null>("save_text", { path, text }),

  openSample: (path: string, raw = false, bits = 64) =>
    call<SampleSummary>("open_sample", { path, raw, bits }),
  listSamples: () => call<SampleSummary[]>("list_samples"),
  closeSample: (sha: string) => call<null>("close_sample", { sha }),
  overview: (sha: string) => call<Overview>("get_overview", { sha }),
  findings: (sha: string) => call<FindingRow[]>("get_findings", { sha }),
  triage: (sha: string) => call<Triage>("get_triage", { sha }),
  jobStatus: (sha: string) => call<Triage["jobs"]>("job_status", { sha }),
  setVerdict: (sha: string, factId: string, verdict: Verdict | null) =>
    call<null>("set_verdict", { sha, fact_id: factId, verdict }),
  exportIocs: (sha: string, fmt: "csv" | "json") => call<string>("export_iocs", { sha, fmt }),
  openPayload: (sha: string, payloadSha: string) =>
    call<SampleSummary>("open_payload", { sha, payload_sha: payloadSha }),
  exportPayload: (sha: string, payloadSha: string, path: string) =>
    call<null>("export_payload", { sha, payload_sha: payloadSha, path }),
  getStrings: (
    sha: string,
    category: string | null,
    query: string,
    offset: number,
    limit: number,
    origin: string | null = null,
  ) => call<StringsPage>("get_strings", { sha, category, query, offset, limit, origin }),
  extensions: () => call<Extension[]>("get_extensions"),
  runExtension: (sha: string, extId: EngineId, force = false) =>
    call<null>("run_extension", { sha, ext_id: extId, force }),
  xrefsTo: (sha: string, rva: number) => call<XrefRow[]>("xrefs_to", { sha, rva }),
  annotate: (sha: string, kind: AnnotationKind, value: string, address: number | null, target: string | null = null) =>
    call<Annotation>("annotate", { sha, kind, value, address, target }),
  deleteAnnotation: (sha: string, annotationId: number) =>
    call<null>("delete_annotation", { sha, annotation_id: annotationId }),
  listAnnotations: (sha: string) => call<Annotation[]>("list_annotations", { sha }),
  mitre: (sha: string) => call<MitreRow[]>("get_mitre", { sha }),
  discoveryStatus: (sha: string) => call<DiscoveryStatus>("discovery_status", { sha }),
  functions: (sha: string) => call<FunctionSummary[]>("list_functions", { sha }),
  fn: (sha: string, start: number) => call<FunctionData>("get_function", { sha, start }),
  locate: (sha: string, rva: number) => call<Location>("locate", { sha, rva }),
  disassemble: (sha: string, rva: number, count = 96) =>
    call<InstructionData[]>("disassemble", { sha, rva, count }),
  readBytes: (sha: string, offset: number, length: number) =>
    call<ByteChunk>("read_bytes", { sha, offset, length }),
  decompiled: (sha: string, rva: number) => call<Decompiled>("get_decompiled", { sha, rva }),
  relations: (sha: string, start: number, callers: number, callees: number) =>
    call<Relations>("get_relations", { sha, start, callers, callees }),
  search: (sha: string, kind: SearchKind, query: string, limit = 500) =>
    call<SearchResult>("search", { sha, kind, query, limit }),
  symbols: (sha: string) => call<Symbols>("get_symbols", { sha }),
  memoryMap: (sha: string) => call<MemoryMapData>("get_memory_map", { sha }),
  aiStatus: () => call<AiStatus>("ai_status"),
  aiPreview: (sha: string) => call<AiPreview>("ai_preview", { sha }),
  aiAnalyse: (sha: string, confirmedHash: string, force: boolean, endpoint: number) =>
    call<null>("ai_analyse", { sha, confirmed_hash: confirmedHash, force, endpoint }),
  aiReport: (sha: string) => call<AiReport | null>("get_ai_report", { sha }),
  exportYara: (sha: string) => call<string>("export_yara", { sha }),
  exportSigma: (sha: string) => call<string | null>("export_sigma", { sha }),

  newSession: (path: string) => call<{ path: string }>("new_session", { path }),
  openSession: (path: string) => call<SampleSummary[]>("open_session", { path }),
};
