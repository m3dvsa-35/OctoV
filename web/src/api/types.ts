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

export interface FindingRow {
  id: string;
  kind: "indicator" | "rule";
  name: string;
  severity: Severity;
  mitre: string[];
  mitre_names: Record<string, string>;
  description: string;
  rva: number | null;
  offset: number | null;
  evidence: Evidence[];
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
}

export interface Capabilities {
  native_dialogs: boolean;
}
