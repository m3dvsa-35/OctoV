"""Speed check of the Ghidra decompiler on System32 PEs of different sizes.

Usage: .venv/Scripts/python scripts/ghidra_speed.py [--sizes-mb 0.05 0.3 1 5 10 20] [--functions 30]
Needs the ghidra extra, Ghidra 12.x and a JDK >= 21 (``octov ext status``).
Per file: analysis seconds (first open), reopen seconds (saved project), decompile p50/p95 of
uncached functions and p50 of the same functions served from the cache.
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SYSTEM32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"


def pick_files(sizes_mb: list[float]) -> list[Path]:
    """The System32 .dll/.exe closest to each requested size."""
    sized = []
    for pattern in ("*.dll", "*.exe"):
        for path in SYSTEM32.glob(pattern):
            try:
                sized.append((path.stat().st_size, path))
            except OSError:
                continue
    picked: list[Path] = []
    for mb in sizes_mb:
        target = mb * 1024 * 1024
        best = min((s for s in sized if s[1] not in picked), key=lambda s: abs(s[0] - target))
        picked.append(best[1])
    return picked


def wait_ghidra(api: Any, sha: str, limit_s: float) -> dict[str, Any]:
    end = time.monotonic() + limit_s
    while True:
        job: dict[str, Any] = api.job_status(sha).get("ghidra", {"state": "unavailable"})
        if job["state"] not in ("queued", "running") or time.monotonic() > end:
            return job
        time.sleep(0.2)


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(q * (len(ordered) - 1)))]


def measure(api: Any, path: Path, functions: int, limit_s: float) -> dict[str, Any]:
    from octov.app.api import ApiError

    row: dict[str, Any] = {"file": path.name, "mb": round(path.stat().st_size / 1048576, 2)}
    try:
        sha = api.open_sample(str(path))["sha256"]
    except (ApiError, OSError) as exc:
        return row | {"error": str(exc)[:80]}
    start = time.monotonic()
    job = wait_ghidra(api, sha, limit_s)
    row["analysis_s"] = round(time.monotonic() - start, 1)
    if job["state"] != "done":
        api.close_sample(sha)
        return row | {"error": f"{job['state']}: {job.get('error')}"}
    while api.discovery_status(sha)["state"] == "running":
        time.sleep(0.2)
    starts = [f["start"] for f in api.list_functions(sha)]
    step = max(1, len(starts) // functions)
    sample = starts[::step][:functions]
    fresh: list[float] = []
    cached: list[float] = []
    asked: list[int] = []
    for rva in sample:
        t0 = time.perf_counter()
        try:
            out = api.get_decompiled(sha, rva)
        except ApiError:
            continue
        if not out["cached"]:  # the ahead-of-time pass may already have cached a few
            fresh.append(time.perf_counter() - t0)
        asked.append(rva)
    for rva in asked:
        t0 = time.perf_counter()
        api.get_decompiled(sha, rva)
        cached.append(time.perf_counter() - t0)
    row["functions"] = len(starts)
    row["decompiled"] = len(asked)
    if fresh:
        row["decomp_p50_s"] = round(statistics.median(fresh), 3)
        row["decomp_p95_s"] = round(percentile(fresh, 0.95), 3)
    if cached:
        row["cached_p50_ms"] = round(statistics.median(cached) * 1000, 1)
    api.close_sample(sha)
    start = time.monotonic()
    sha = api.open_sample(str(path))["sha256"]
    job = wait_ghidra(api, sha, limit_s)
    row["reopen_s"] = round(time.monotonic() - start, 1)
    if job["state"] != "done":
        row["error"] = f"reopen {job['state']}: {job.get('error')}"
    api.close_sample(sha)
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sizes-mb", type=float, nargs="+", default=[0.05, 0.3, 1, 5, 10, 20])
    parser.add_argument("--functions", type=int, default=30)
    args = parser.parse_args()

    from octov.app.api import WorkbenchApi
    from octov.core.config import Config

    config = Config()
    work = Path(tempfile.mkdtemp(prefix="octov-ghidra-speed-"))
    api = WorkbenchApi(
        config,
        settings_path=work / "ui.json",
        workspace_dir=work / "ws",
        cache_dir=work / "cache",
        ghidra_root=work / "projects",
    )
    api.set_settings({"extensions_auto_run": {"capa": False, "floss": False, "ghidra": True}})
    limit = config.ghidra.analysis_timeout_s + 180
    try:
        for path in pick_files(args.sizes_mb):
            print(measure(api, path, args.functions, limit), flush=True)
    finally:
        api.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
