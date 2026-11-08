"""Full-pipeline System32 baseline, parallel: one JSON line per file.

Usage: .venv/Scripts/python scripts/baseline_sweep.py out.jsonl   (~15 min, 12 workers)
Each line: file, size, fast_s, slow_s, score, band, high (high-severity fact ids),
failed_jobs; or skip / timeout.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from multiprocessing import Pool
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SYSTEM32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
SLOW_CAP = 900.0
_api: Any = None


def _init() -> None:
    global _api
    from octov.app.api import WorkbenchApi
    from octov.core.config import Config

    d = Path(tempfile.mkdtemp(prefix="octov-sweep-"))
    _api = WorkbenchApi(Config(), settings_path=d / "ui.json", workspace_dir=d / "ws")


def one(path_str: str) -> dict[str, object]:
    from octov.app.api import ApiError

    path = Path(path_str)
    row: dict[str, object] = {"file": path.name, "size": path.stat().st_size}
    t0 = time.perf_counter()
    try:
        sha = _api.open_sample(path_str)["sha256"]
    except (ApiError, PermissionError, OSError) as exc:
        row["skip"] = str(exc)[:80]
        return row
    row["fast_s"] = round(time.perf_counter() - t0, 2)
    t1 = time.perf_counter()
    while any(j["state"] in ("queued", "running") for j in _api.job_status(sha).values()):
        if time.perf_counter() - t1 > SLOW_CAP:
            row["timeout"] = True
            break
        time.sleep(0.05)
    row["slow_s"] = round(time.perf_counter() - t1, 2)
    if not row.get("timeout"):
        tri = _api.get_triage(sha)
        row["score"] = tri["score"]["score"]
        row["band"] = tri["score"]["band"]
        row["high"] = [c["source_id"] for c in tri["capabilities"] if c["severity"] == "high"]
        row["failed_jobs"] = [k for k, j in tri["jobs"].items() if j["state"] == "failed"]
    _api.close_sample(sha)
    return row


def main() -> None:
    out = Path(sys.argv[1])
    files = sorted(p for p in SYSTEM32.iterdir() if p.suffix.lower() in (".exe", ".dll"))
    files.sort(key=lambda p: p.stat().st_size, reverse=True)  # slow ones first
    workers = min(12, max(1, (os.cpu_count() or 2) - 1))
    with (
        out.open("w", encoding="utf-8") as fh,
        Pool(workers, initializer=_init, maxtasksperchild=40) as pool,
    ):
        for row in pool.imap_unordered(one, [str(p) for p in files]):
            fh.write(json.dumps(row) + "\n")
            fh.flush()
    print("done", len(files), "files,", workers, "workers")


if __name__ == "__main__":
    main()
