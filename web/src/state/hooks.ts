import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { FunctionData, InstructionData } from "../api/types";

const fnCache = new Map<string, FunctionData>();

/** Function CFG for (sha, start), cached across views (disassembly and graph share it). */
export function useFunctionData(sha: string | null, start: number | null): FunctionData | null {
  const key = sha && start !== null ? `${sha}:${start}` : null;
  const [data, setData] = useState<FunctionData | null>(key ? (fnCache.get(key) ?? null) : null);
  useEffect(() => {
    if (!key || !sha || start === null) {
      setData(null);
      return;
    }
    const cached = fnCache.get(key);
    if (cached) {
      setData(cached);
      return;
    }
    let live = true;
    void api.fn(sha, start).then(
      (fn) => {
        if (fnCache.size > 64) fnCache.delete(fnCache.keys().next().value as string);
        fnCache.set(key, fn);
        if (live) setData(fn);
      },
      () => live && setData(null),
    );
    return () => {
      live = false;
    };
  }, [key, sha, start]);
  return data;
}

/** Linear disassembly for addresses outside any discovered function. */
export function useLinear(sha: string | null, rva: number | null, enabled: boolean): InstructionData[] {
  const [rows, setRows] = useState<InstructionData[]>([]);
  useEffect(() => {
    if (!enabled || !sha || rva === null) {
      setRows([]);
      return;
    }
    let live = true;
    void api.disassemble(sha, rva).then((r) => live && setRows(r), () => live && setRows([]));
    return () => {
      live = false;
    };
  }, [sha, rva, enabled]);
  return rows;
}
