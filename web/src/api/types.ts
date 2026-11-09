export type Severity = "high" | "medium" | "low" | "info";

export interface SampleSummary {
  sha256: string;
  name: string;
  path: string;
  format: "pe" | "raw";
  size: number;
  counts: Record<Severity, number>;
}

export interface SectionInfo {
  name: string;
  va: number;
  vsize: number;
  raw_offset: number;
  raw_size: number;
  entropy: number;
  perm: string;
}

export interface Overview {
  name: string;
  path: string;
  size: number;
  format: "pe" | "raw";
  hashes: { md5: string; sha1: string; sha256: string; imphash: string | null };
  entropy: number;
  bits?: number;
  machine?: string;
  is_64bit?: boolean;
  is_dll?: boolean;
  subsystem?: string;
  compile_time?: string;
  entry_point?: number;
  image_base?: number;
  signature?: { present: boolean; verified: boolean | null };
  overlay_size?: number;
  sections?: SectionInfo[];
  imports?: Record<string, string[]>;
  exports?: string[];
  export_count?: number;
}

export interface Evidence {
  type?: string;
  value?: string;
  detail: string;
  offset?: number | null;
  rva?: number | null;
}

export type FactKind =
  | "rule"
  | "indicator"
  | "crypto_constant"
  | "embedded_payload"
  | "packer"
  | "ioc"
  | "capability"
  | "obfuscated_strings"
  | "hidden_ioc";
export type Verdict = "false_positive" | "benign" | "confirmed";

/** A fact (one automatic result) as served by get_findings / triage capabilities. */
export interface FindingRow {
  id: string; // stable fact id, e.g. "rule:EVA-001:0x2000"
  source_id: string; // rule / indicator id shown to the analyst
  kind: FactKind;
  title: string;
  name: string;
  description: string;
  severity: Severity;
  mitre: string[];
  tags: string[];
  mitre_names: Record<string, string>;
  rva: number | null;
  offset: number | null;
  evidence: Evidence[];
  explain_key: string | null;
  confidence: number;
  verdict: Verdict | null;
}

/** Triage capability rows are raw fact dicts (no derived location/name fields). */
export type CapabilityRow = Omit<FindingRow, "rva" | "offset" | "mitre_names" | "name" | "description">;

export interface Contribution {
  fact_id: string;
  points: number;
  title: string;
  severity: Severity;
}

export interface Triage {
  score: { score: number; band: "low" | "medium" | "high"; contributions: Contribution[] };
  packer: { packed: boolean; confidence: number; packer: string | null; reasons: string[] } | null;
  capabilities: CapabilityRow[];
  iocs: {
    type: string;
    value: string;
    offsets: number[];
    benign_hint: string | null;
    fact_id: string | null;
    verdict: Verdict | null;
  }[];
  iocs_total: number;
  payloads: { offset: number; size: number; kind: string; where: string; sha256: string }[];
  top_functions: { start: number; name: string; score: number; reasons: string[] }[];
  attack: MitreRow[];
  orphaned_verdicts: { fact_id: string; verdict: Verdict }[];
  jobs: Record<string, JobState>;
}

export interface JobState {
  state: string;
  error: string | null;
  elapsed_s: number | null;
  cached: boolean;
}

export type EngineId = "capa" | "floss" | "ghidra";

export interface Extension {
  id: EngineId;
  installed: boolean;
  ready: boolean;
  version: string | null;
  rules_version: string | null;
  reason_key: string | null;
  install_cmd: string;
  setup_cmd: string | null;
  auto_run: boolean;
}

export interface MitreRow {
  technique: string;
  name: string;
  tactic: string;
  severity: Severity;
  hits: number;
  sources: string[];
}

export interface DiscoveryStatus {
  state: "running" | "done" | "failed";
  functions: number;
  error: string | null;
}

export interface FunctionSummary {
  start: number;
  name: string;
  suggested: boolean;
  blocks: number;
  size: number;
  is_entry: boolean;
}

export interface InstructionData {
  address: number;
  text: string;
  bytes: string;
  mnemonic: string;
  operands: string;
  target: number | null;
  comment: string | null;
}

export type EdgeKind = "true" | "false" | "jump" | "fallthrough";

export interface BlockData {
  start: number;
  end: number;
  indirect: boolean;
  successors: { target: number; kind: EdgeKind }[];
  instructions: InstructionData[];
}

export interface FunctionData {
  start: number;
  name: string;
  calls: number[];
  blocks: BlockData[];
}

export interface Location {
  rva: number;
  offset: number | null;
  function: number | null;
}

export interface ByteChunk {
  offset: number;
  data: string; // base64
  total: number;
}

export interface Settings {
  language: "en" | "az";
  theme: "dark" | "light";
  compact: boolean;
  extensions_auto_run: Record<EngineId, boolean>;
}

export type AnnotationKind = "name" | "comment" | "bookmark" | "verdict";

export interface Annotation {
  id: number;
  kind: AnnotationKind;
  address: number | null;
  target: string | null;
  value: string;
}

export interface StringRow {
  value: string;
  encoding: string;
  offset: number;
  rva: number | null;
  section: string | null;
  category: string | null;
  origin: "static" | "stack" | "tight" | "decoded";
  function: number | null;
  xrefs: number | null;
}

export interface StringsPage {
  total: number;
  items: StringRow[];
}

export interface XrefRow {
  src: number;
  kind: string;
  func: number | null;
  func_name: string | null;
}

export interface Capabilities {
  native_dialogs: boolean;
}

export type LineMark =
  | { kind: "fact"; fact_id: string; severity: Severity }
  | { kind: "api"; api: string; family: string };

export interface PseudoLine {
  text: string;
  rvas: number[];
  marks: LineMark[];
}

export interface Decompiled {
  entry_rva: number;
  name: string;
  lines: PseudoLine[];
  warnings: string[];
  octov_function: number | null;
  cached: boolean;
}
