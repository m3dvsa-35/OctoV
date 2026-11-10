import ELK from "elkjs/lib/elk-api.js";

/** One ELK instance for every graph view; layout runs in a worker, never on the UI thread. */
export const elk = new ELK({
  workerFactory: () => new Worker(new URL("elkjs/lib/elk-worker.min.js", import.meta.url), { type: "module" }),
});
