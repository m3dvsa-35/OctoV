"""WorkbenchApi: the contract between the web UI and the Python analysis core.

Every public method takes and returns JSON-serialisable values. The same object
is exposed to the desktop window through pywebview's JS bridge (no network) and,
for development, through the token-protected loopback server in ``devserver``.
Methods may be called from several threads; shared state is guarded by a lock.

Analysis runs through the analyzer pipeline: fast analyzers finish inside
``open_sample``, slow ones (functions, xrefs, naming, ranking) stream in and are
reported by ``job_status``. Analyst annotations (names, comments, bookmarks,
verdicts) persist in the open session or, if none is open, in a per-sample
workspace session under ``workspace_dir``.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import shutil
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from octov.core.ai import client as ai_client
from octov.core.ai.bundle import Bundle, BundleInput, FunctionEvidence, build_bundle
from octov.core.ai.client import AIError
from octov.core.ai.report import parse_report, system_prompt
from octov.core.analysis import search as search_mod
from octov.core.analysis.analyzers import default_analyzers
from octov.core.analysis.callgraph import CallGraph, apis_of
from octov.core.analysis.carve import payload_zip
from octov.core.analysis.facts import Fact, facts_from_findings, facts_from_indicators
from octov.core.analysis.iocs import ioc_fact_id, iocs_csv, iocs_json
from octov.core.analysis.naming import API_FAMILIES
from octov.core.analysis.pipeline import AnalysisContext, AnalyzerStatus, Pipeline
from octov.core.analysis.report import build_triage, ioc_rows
from octov.core.analysis.scoring import IGNORED_VERDICTS, SUSPICIOUS_FAMILIES, risk_score
from octov.core.config import THEMES, Config
from octov.core.export.sigma_gen import generate_sigma
from octov.core.export.yara_gen import generate_yara
from octov.core.i18n import LANGUAGES
from octov.core.mitre import technique_name
from octov.core.session.session import Session, SessionError
from octov.core.static.analysis import (
    RawAnalysis,
    RawSample,
    StaticAnalysis,
    analyze,
    analyze_raw,
    default_rules,
    rule_set,
)
from octov.core.static.cfg import Function
from octov.core.static.disasm import Disassembler, ImageView, RawView
from octov.core.static.pe_parser import (
    Hashes,
    PEParseError,
    PEReport,
    normalize_api,
    shannon_entropy,
)
from octov.core.static.rules import Rule, RuleError
from octov.ext import (
    ALL_EXTENSIONS,
    DEFAULT_RULES_ROOT,
    DEFAULT_SIGS_ROOT,
    ENGINES,
    ExtensionStatus,
    capa_rules_dir,
    capa_sigs_dir,
    extension_status,
)
from octov.ext import cache as ext_cache
from octov.ext import capa as capa_ext
from octov.ext import floss as floss_ext
from octov.ext.apply import apply_capa, apply_floss
from octov.ext.ghidra.discover import ghidra_status
from octov.ext.ghidra.manager import (
    GhidraManager,
    WorkerCommand,
    cleanup_projects,
    default_project_root,
    worker_command,
)
from octov.ext.ghidra.model import (
    DecompiledFunction,
    annotation_hash,
    line_marks,
    suspicious_apis,
)
from octov.ext.ghidra.model import cache_path as decomp_cache_path
from octov.ext.ghidra.protocol import GhidraError
from octov.ext.queue import QUEUES
from octov.ext.runner import EngineError, parse_json, run_engine

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
MAX_READ = 1 << 20  # largest hex chunk a single call may return
MAX_STRINGS_PAGE = 2000
VERDICTS = ("false_positive", "benign", "confirmed")
PREDECOMPILE = 10  # top-ranked functions decompiled into the cache right after analysis
_DECOMP_ATTEMPTS = 3  # re-asks when the analyst renamed something while Ghidra was answering
_REAP_EVERY_S = 30.0
MAX_DEPTH = 3  # relations: calls away from the centre, each way
MAX_RELATION_NODES = 60
MAX_SEARCH_HITS = 2000
MAX_EXPORTS = 5000
AI_FUNCTIONS = 12  # top-ranked functions (plus the entry point) described to the AI analyst
AI_ASM_LINES = 40  # instructions shown for a function when no pseudo-C is cached


class ApiError(Exception):
    """User-facing error; the message is shown in the UI."""


@dataclass
class _Sample:
    path: Path
    data: bytes
    analysis: StaticAnalysis | RawAnalysis
    ctx: AnalysisContext
    pipeline: Pipeline
    parent: str | None = None
    store: Session | None = field(default=None, repr=False)  # workspace session, if any
    ghidra_version: str | None = None  # set when the decompiler was scheduled for this sample
    decomp_entries: dict[int, int] = field(default_factory=dict)  # address -> Ghidra function
    callgraph: CallGraph | None = field(default=None, repr=False)  # built on first use
    memory_map: dict[str, Any] | None = field(default=None, repr=False)
    ai_running: bool = False  # one AI request per sample at a time

    @property
    def hashes(self) -> Hashes:
        if isinstance(self.analysis, StaticAnalysis):
            return self.analysis.report.hashes
        return self.analysis.sample.hashes

    @property
    def sha(self) -> str:
        return self.hashes.sha256

    @property
    def report(self) -> PEReport | None:
        return self.analysis.report if isinstance(self.analysis, StaticAnalysis) else None

    @property
    def raw(self) -> RawSample | None:
        return self.analysis.sample if isinstance(self.analysis, RawAnalysis) else None

    @property
    def functions(self) -> dict[int, Function]:
        return self.ctx.functions

    def view(self) -> ImageView | RawView:
        if self.report is not None:
            return ImageView(self.data, self.report)
        assert self.raw is not None
        return RawView(self.data, bits=self.raw.bits)


def _perm(readable: bool, writable: bool, executable: bool) -> str:
    return ("R" if readable else "-") + ("W" if writable else "-") + ("X" if executable else "-")


class WorkbenchApi:
    def __init__(
        self,
        config: Config | None = None,
        settings_path: Path | None = None,
        workspace_dir: Path | None = None,
        cache_dir: Path | None = None,
        rules_root: Path | None = None,
        sigs_root: Path | None = None,
        ghidra_factory: Callable[[], WorkerCommand] | None = None,
        ghidra_root: Path | None = None,
    ) -> None:
        self._config = config or Config()
        self._cache_dir = cache_dir or Path.home() / ".octov" / "cache"
        self._rules_root = rules_root or DEFAULT_RULES_ROOT.expanduser()
        self._sigs_root = sigs_root or DEFAULT_SIGS_ROOT.expanduser()
        self._settings_path = settings_path or Path.home() / ".octov" / "ui.json"
        self._workspace_dir = workspace_dir or Path.home() / ".octov" / "workspaces"
        self._lock = threading.RLock()
        self._samples: dict[str, _Sample] = {}
        self._session: Session | None = None
        try:
            self._rules: tuple[Rule, ...] = rule_set(self._config.rules.paths)
        except RuleError:
            self._rules = default_rules()
        self._settings = self._load_settings()
        ghidra_cfg = self._config.ghidra
        self._ghidra_root = ghidra_root or default_project_root()
        self._ghidra = GhidraManager(
            ghidra_cfg, ghidra_factory or (lambda: worker_command(ghidra_cfg)), self._ghidra_root
        )
        self._ghidra_started = False
        self._ghidra_stop = threading.Event()

    # -- settings & strings ------------------------------------------------------

    def _load_settings(self) -> dict[str, Any]:
        settings: dict[str, Any] = {
            "language": self._config.ui.language,
            "theme": self._config.ui.theme,
            "compact": False,
            "extensions_auto_run": {e: True for e in ALL_EXTENSIONS},
        }
        try:
            stored = json.loads(self._settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return settings
        if stored.get("language") in LANGUAGES:
            settings["language"] = stored["language"]
        if stored.get("theme") in THEMES:
            settings["theme"] = stored["theme"]
        if isinstance(stored.get("compact"), bool):
            settings["compact"] = stored["compact"]
        auto = stored.get("extensions_auto_run")
        if isinstance(auto, dict):
            for e in ALL_EXTENSIONS:
                if isinstance(auto.get(e), bool):
                    settings["extensions_auto_run"][e] = auto[e]
        return settings

    def get_settings(self) -> dict[str, Any]:
        out = dict(self._settings)
        out["extensions_auto_run"] = dict(self._settings["extensions_auto_run"])
        return out

    def set_settings(self, settings: dict[str, Any]) -> dict[str, Any]:
        lang = settings.get("language", self._settings["language"])
        theme = settings.get("theme", self._settings["theme"])
        compact = settings.get("compact", self._settings["compact"])
        auto = {**self._settings["extensions_auto_run"], **settings.get("extensions_auto_run", {})}
        if (
            lang not in LANGUAGES
            or theme not in THEMES
            or not isinstance(compact, bool)
            or set(auto) != set(ALL_EXTENSIONS)
            or not all(isinstance(v, bool) for v in auto.values())
        ):
            raise ApiError(f"invalid settings: {settings}")
        self._settings = {
            "language": lang,
            "theme": theme,
            "compact": compact,
            "extensions_auto_run": auto,
        }
        try:
            self._settings_path.parent.mkdir(parents=True, exist_ok=True)
            self._settings_path.write_text(json.dumps(self._settings), encoding="utf-8")
        except OSError as exc:
            raise ApiError(f"cannot save settings: {exc}") from exc
        return self.get_settings()

    # -- host integration (overridden by the desktop shell) -------------------------

    def capabilities(self) -> dict[str, bool]:
        return {"native_dialogs": False}

    def choose_file(self) -> str | None:
        """Native open-file dialog; ``None`` in browser mode (the UI asks for a path)."""
        return None

    def choose_save_path(self, suggested: str) -> str | None:
        """Native save dialog; ``None`` in browser mode."""
        return None

    def save_text(self, path: str, text: str) -> None:
        try:
            Path(path).write_text(text, encoding="utf-8")
        except OSError as exc:
            raise ApiError(f"cannot save {path}: {exc.strerror or exc}") from exc

    def strings(self, lang: str) -> dict[str, str]:
        base = dict(LANGUAGES["en"])
        base.update(LANGUAGES.get(lang, {}))
        return base

    # -- samples -------------------------------------------------------------------

    def open_sample(self, path: str, raw: bool = False, bits: int = 64) -> dict[str, Any]:
        file = Path(path)
        try:
            data = file.read_bytes()
        except OSError as exc:
            raise ApiError(f"cannot read {path}: {exc.strerror or exc}") from exc
        return self._open_bytes(data, file, raw=raw, bits=bits)

    def _open_bytes(
        self, data: bytes, file: Path, raw: bool = False, bits: int = 64, parent: str | None = None
    ) -> dict[str, Any]:
        limit = self._config.static.max_file_size_mb * 1024 * 1024
        if len(data) > limit:
            raise ApiError(f"file exceeds {self._config.static.max_file_size_mb} MB limit")
        try:
            analysis: StaticAnalysis | RawAnalysis
            if raw:
                raw_result = analyze_raw(data, self._rules, bits=bits)
                raw_result.sample.path = str(file)
                analysis = raw_result
                ctx = AnalysisContext(data, None, bits, raw_result.findings)
            else:
                pe_result = analyze(data, self._rules)
                pe_result.report.path = str(file)
                analysis = pe_result
                ctx = AnalysisContext(
                    data,
                    pe_result.report,
                    64 if pe_result.report.is_64bit else 32,
                    pe_result.findings,
                )
        except PEParseError as exc:
            raise ApiError(f"{exc} - open it as a raw code blob instead") from exc
        except ValueError as exc:
            raise ApiError(str(exc)) from exc

        sha = analysis.to_dict()["hashes"]["sha256"]
        with self._lock:
            existing = self._samples.get(sha)
            if existing is not None:
                return self._summary(existing)
        pipeline = Pipeline(default_analyzers())
        pipeline.run_fast(ctx)
        sample = _Sample(file, data, analysis, ctx, pipeline, parent=parent)
        with self._lock:
            existing = self._samples.get(sha)  # opened concurrently meanwhile: keep the first
            if existing is not None:
                return self._summary(existing)
            self._samples[sha] = sample
            if self._session is not None:
                self._persist(self._session, sample)
                self._merge_workspace(self._session, sample)
            else:
                ws = self._workspace_dir / f"{sha}.octov"
                if ws.is_file():
                    try:
                        sample.store = Session.open(ws)
                    except SessionError:
                        sample.store = None
        pipeline.start_slow(ctx)
        self._schedule_extensions(sample)
        self._schedule_ghidra(sample)
        return self._summary(sample)

    def _persist(self, session: Session, sample: _Sample) -> None:
        try:
            session.add_sample(sample.analysis)
            session.commit()
        except SessionError as exc:
            raise ApiError(str(exc)) from exc

    def _merge_workspace(self, session: Session, sample: _Sample) -> None:
        """Copy the sample's workspace annotations into ``session`` (spec 9.3).

        The session wins: a name/verdict it already has for the same address/fact is kept;
        identical comments/bookmarks are not duplicated.
        """
        path = self._workspace_dir / f"{sample.sha}.octov"
        store = sample.store
        if store is None:
            if not path.is_file():
                return
            try:
                store = sample.store = Session.open(path)
            except SessionError:
                return
        have = session.annotations(sample.sha)
        names = {a.address for a in have if a.kind == "name"}
        verdicts = {a.target for a in have if a.kind == "verdict"}
        same = {(a.kind, a.address, a.target, a.value) for a in have}
        try:
            for a in store.annotations(sample.sha):
                if (
                    (a.kind == "name" and a.address in names)
                    or (a.kind == "verdict" and a.target in verdicts)
                    or (a.kind, a.address, a.target, a.value) in same
                ):
                    continue
                session.add_annotation(sample.sha, a.kind, a.value, a.address, a.target)
            session.commit()
        except SessionError as exc:
            raise ApiError(str(exc)) from exc

    def _get(self, sha: str) -> _Sample:
        with self._lock:
            sample = self._samples.get(sha)
        if sample is None:
            raise ApiError(f"unknown sample {sha[:12]}")
        return sample

    def _summary(self, s: _Sample) -> dict[str, Any]:
        counts = {k: 0 for k in _SEVERITY_ORDER}
        verdicts = self._verdicts(s)
        for fact in s.ctx.facts:
            if verdicts.get(fact.id) not in IGNORED_VERDICTS:
                counts[fact.severity] += 1
        return {
            "sha256": s.sha,
            "name": s.path.name,
            "path": str(s.path),
            "format": "pe" if s.report is not None else "raw",
            "size": len(s.data),
            "counts": counts,
            "parent": s.parent,
        }

    def list_samples(self) -> list[dict[str, Any]]:
        with self._lock:
            samples = list(self._samples.values())
        return [self._summary(s) for s in samples]

    def close_sample(self, sha: str) -> None:
        for engine in ENGINES:
            QUEUES[engine].cancel(sha)
        with self._lock:
            sample = self._samples.pop(sha, None)
        self._ghidra.close(sha)
        if sample is not None and sample.store is not None:
            sample.store.commit()
            sample.store.close()

    def get_overview(self, sha: str) -> dict[str, Any]:
        s = self._get(sha)
        h = s.hashes
        base: dict[str, Any] = {
            "name": s.path.name,
            "path": str(s.path),
            "size": len(s.data),
            "hashes": {"md5": h.md5, "sha1": h.sha1, "sha256": h.sha256, "imphash": h.imphash},
        }
        r = s.report
        if r is None:
            assert s.raw is not None
            return base | {"format": "raw", "bits": s.raw.bits, "entropy": s.raw.entropy}
        return base | {
            "format": "pe",
            "machine": r.machine,
            "is_64bit": r.is_64bit,
            "is_dll": r.is_dll,
            "subsystem": r.subsystem,
            "compile_time": r.compile_time.isoformat(),
            "entry_point": r.entry_point,
            "image_base": r.image_base,
            "entropy": r.entropy,
            "signature": {"present": r.signature.present, "verified": r.signature.verified},
            "overlay_size": r.overlay_size,
            "sections": [
                {
                    "name": sec.name,
                    "va": sec.virtual_address,
                    "vsize": sec.virtual_size,
                    "raw_offset": sec.raw_offset,
                    "raw_size": sec.raw_size,
                    "entropy": sec.entropy,
                    "perm": _perm(sec.readable, sec.writable, sec.executable),
                }
                for sec in r.sections
            ],
            "imports": r.imports,
            "exports": r.exports[:2000],
            "export_count": len(r.exports),
        }

    # -- annotations ---------------------------------------------------------------

    def _store(self, s: _Sample, create: bool) -> Session | None:
        """Explicit session if open, else the sample's workspace session (created on demand)."""
        if self._session is not None:
            return self._session
        if s.store is None and create:
            with self._lock:  # one workspace connection per sample, even for parallel calls
                if s.store is None:
                    self._workspace_dir.mkdir(parents=True, exist_ok=True)
                    path = self._workspace_dir / f"{s.sha}.octov"
                    try:
                        s.store = Session.open(path) if path.is_file() else Session.create(path)
                        if s.store.get_sample(s.sha) is None:
                            self._persist(s.store, s)
                    except SessionError as exc:
                        raise ApiError(str(exc)) from exc
        return s.store

    def _annotations(self, s: _Sample, kind: str | None = None) -> list[Any]:
        store = self._store(s, create=False)
        return store.annotations(s.sha, kind) if store is not None else []

    def _verdicts(self, s: _Sample) -> dict[str, str]:
        return {a.target: a.value for a in self._annotations(s, "verdict") if a.target}

    def _names(self, s: _Sample) -> tuple[dict[int, str], dict[int, str]]:
        """(analyst names, suggested names) by function start."""
        own = {a.address: a.value for a in self._annotations(s, "name") if a.address is not None}
        return own, dict(s.ctx.results.get("names", {}))

    def annotate(
        self,
        sha: str,
        kind: str,
        value: str,
        address: int | None = None,
        target: str | None = None,
    ) -> dict[str, Any]:
        s = self._get(sha)
        store = self._store(s, create=True)
        assert store is not None
        try:
            ann_id = store.add_annotation(sha, kind, value, address=address, target=target)
            store.commit()
        except SessionError as exc:
            raise ApiError(str(exc)) from exc
        return {"id": ann_id, "kind": kind, "value": value, "address": address, "target": target}

    def delete_annotation(self, sha: str, annotation_id: int) -> None:
        store = self._store(self._get(sha), create=False)
        if store is not None:
            store.delete_annotation(annotation_id)
            store.commit()

    def list_annotations(self, sha: str) -> list[dict[str, Any]]:
        return [
            {"id": a.id, "kind": a.kind, "address": a.address, "target": a.target, "value": a.value}
            for a in self._annotations(self._get(sha))
        ]

    def set_verdict(self, sha: str, fact_id: str, verdict: str | None) -> None:
        s = self._get(sha)
        if verdict is None:
            for a in self._annotations(s, "verdict"):
                if a.target == fact_id:
                    self.delete_annotation(sha, a.id)
            return
        if verdict not in VERDICTS:
            raise ApiError(f"invalid verdict {verdict!r}")
        self.annotate(sha, "verdict", verdict, target=fact_id)

    # -- findings & triage -------------------------------------------------------------

    @staticmethod
    def _fact_row(fact: Fact, verdict: str | None) -> dict[str, Any]:
        located = next((e for e in fact.evidence if e.rva is not None), None) or next(
            (e for e in fact.evidence if e.offset is not None), None
        )
        return fact.to_dict() | {
            "name": fact.title,
            "description": fact.title,
            "mitre_names": {t: technique_name(t) for t in fact.mitre},
            "rva": located.rva if located else None,
            "offset": located.offset if located else None,
            "verdict": verdict,
        }

    def get_findings(self, sha: str) -> list[dict[str, Any]]:
        s = self._get(sha)
        verdicts = self._verdicts(s)
        rows = [self._fact_row(f, verdicts.get(f.id)) for f in list(s.ctx.facts)]
        rows.sort(key=lambda r: (_SEVERITY_ORDER[r["severity"]], r["kind"], r["source_id"]))
        return rows

    def get_mitre(self, sha: str) -> list[dict[str, Any]]:
        return list(self.get_triage(sha)["attack"])

    def get_triage(self, sha: str) -> dict[str, Any]:
        s = self._get(sha)
        own, suggested = self._names(s)
        return build_triage(s.ctx, self._verdicts(s), suggested | own, s.pipeline.status())

    def job_status(self, sha: str) -> dict[str, dict[str, Any]]:
        return self._get(sha).pipeline.status()

    def discovery_status(self, sha: str) -> dict[str, Any]:
        """Function discovery state (kept for the code views)."""
        s = self._get(sha)
        job = s.pipeline.status().get("functions", {"state": "done", "error": None})
        state = {"queued": "running", "running": "running", "done": "done"}.get(
            job["state"], "failed"
        )
        return {"state": state, "functions": len(s.functions), "error": job["error"]}

    def get_strings(
        self,
        sha: str,
        category: str | None = None,
        query: str = "",
        offset: int = 0,
        limit: int = 500,
        origin: str | None = None,
    ) -> dict[str, Any]:
        s = self._get(sha)
        items = list(s.ctx.results.get("strings", []))
        if origin == "recovered":
            items = [x for x in items if x.origin != "static"]
        elif origin:
            items = [x for x in items if x.origin == origin]
        if category:
            items = [x for x in items if x.category == category]
        if query:
            q = query.lower()
            items = [x for x in items if q in x.value.lower()]
        xrefs = s.ctx.results.get("xrefs")
        page = items[max(0, offset) : max(0, offset) + max(0, min(limit, MAX_STRINGS_PAGE))]
        return {
            "total": len(items),
            "items": [
                {
                    "value": x.value,
                    "encoding": x.encoding,
                    "offset": x.offset,
                    "rva": x.rva,
                    "section": x.section,
                    "category": x.category,
                    "origin": x.origin,
                    "function": x.function,
                    "xrefs": len(xrefs.to(x.rva))
                    if xrefs is not None and x.rva is not None
                    else None,
                }
                for x in page
            ],
        }

    def get_iocs(self, sha: str) -> list[dict[str, Any]]:
        """Every IOC (the triage report only carries the first ``MAX_TRIAGE_IOCS``)."""
        s = self._get(sha)
        return ioc_rows(s.ctx, self._verdicts(s))

    def export_iocs(self, sha: str, fmt: str = "csv") -> str:
        """IOC list minus those the analyst marked false positive / benign."""
        s = self._get(sha)
        verdicts = self._verdicts(s)
        iocs = [
            i
            for i in s.ctx.results.get("iocs", [])
            if verdicts.get(ioc_fact_id(i)) not in IGNORED_VERDICTS
        ]
        if fmt == "json":
            return iocs_json(iocs)
        if fmt == "csv":
            return iocs_csv(iocs)
        raise ApiError(f"unsupported IOC format {fmt!r}")

    def xrefs_to(self, sha: str, rva: int) -> list[dict[str, Any]]:
        s = self._get(sha)
        xrefs = s.ctx.results.get("xrefs")
        if xrefs is None:
            return []
        own, suggested = self._names(s)
        names = suggested | own
        return [
            {
                "src": x.src,
                "kind": x.kind,
                "func": x.func,
                "func_name": names.get(x.func, f"sub_{x.func:x}") if x.func is not None else None,
            }
            for x in xrefs.to(rva)
        ]

    # -- payloads ------------------------------------------------------------------

    def list_payloads(self, sha: str) -> list[dict[str, Any]]:
        return list(self.get_triage(sha)["payloads"])

    def _payload_bytes(self, sha: str, payload_sha: str) -> tuple[bytes, Any]:
        s = self._get(sha)
        for p in s.ctx.results.get("payloads", []):
            if p.sha256 == payload_sha:
                return s.data[p.offset : p.offset + p.size], p
        raise ApiError(f"no payload {payload_sha[:12]} in this sample")

    def open_payload(self, sha: str, payload_sha: str) -> dict[str, Any]:
        data, p = self._payload_bytes(sha, payload_sha)
        parent = self._get(sha)
        label = Path(f"{parent.path.name}@{p.offset:#x}")
        store = self._store(parent, create=False)
        if store is not None:
            store.add_payload(sha, p, data)
            store.commit()
        return self._open_bytes(data, label, raw=p.kind != "pe", parent=sha)

    def export_payload(self, sha: str, payload_sha: str, path: str) -> None:
        if not path.lower().endswith(".zip"):
            raise ApiError("payloads are only exported as encrypted .zip (password: infected)")
        data, p = self._payload_bytes(sha, payload_sha)
        try:
            Path(path).write_bytes(payload_zip(data, f"{p.sha256}.bin"))
        except OSError as exc:
            raise ApiError(f"cannot save {path}: {exc.strerror or exc}") from exc

    # -- code ------------------------------------------------------------------------

    def list_functions(self, sha: str) -> list[dict[str, Any]]:
        s = self._get(sha)
        entry = s.report.entry_point if s.report is not None else 0
        exports = {rva: n for n, rva in s.report.export_rvas.items()} if s.report else {}
        own, suggested = self._names(s)
        name_of = self._namer(s)
        out = []
        for start, fn in sorted(s.functions.items()):
            name = name_of(start)
            out.append(
                {
                    "start": start,
                    "name": name,
                    "suggested": start not in own and start not in exports and start in suggested,
                    "blocks": len(fn.blocks),
                    "size": fn.size,
                    "is_entry": start == entry,
                }
            )
        return out

    def _namer(self, s: _Sample) -> Callable[[int], str]:
        """Function name as every view shows it: analyst, export, suggested, ``sub_…``."""
        exports = {rva: n for n, rva in s.report.export_rvas.items()} if s.report else {}
        own, suggested = self._names(s)

        def name_of(start: int) -> str:
            return own.get(start) or exports.get(start) or suggested.get(start) or f"sub_{start:x}"

        return name_of

    def get_function(self, sha: str, start: int) -> dict[str, Any]:
        s = self._get(sha)
        fn = s.functions.get(start)
        if fn is None:
            raise ApiError(f"no function at {start:#x}")
        data = fn.to_dict()
        for block, raw in zip(
            sorted(fn.blocks.values(), key=lambda b: b.start), data["blocks"], strict=True
        ):
            for insn, out in zip(block.instructions, raw["instructions"], strict=True):
                out["target"] = insn.target
                out["comment"] = insn.comment
                out["mnemonic"] = insn.mnemonic
                out["operands"] = insn.op_str
                out["data_ref"] = insn.data_ref
        name = next(f["name"] for f in self.list_functions(sha) if f["start"] == start)
        data["name"] = name
        return data

    def _offset_of(self, s: _Sample, rva: int) -> int | None:
        if s.report is None:
            return rva if 0 <= rva < len(s.data) else None
        for sec in s.report.sections:
            if sec.raw_size and sec.virtual_address <= rva < sec.virtual_address + sec.raw_size:
                return sec.raw_offset + (rva - sec.virtual_address)
        return None

    def locate(self, sha: str, rva: int) -> dict[str, Any]:
        s = self._get(sha)
        fn = s.ctx.index.lookup(rva) if s.ctx.index is not None else None
        return {"rva": rva, "offset": self._offset_of(s, rva), "function": fn.start if fn else None}

    def disassemble(self, sha: str, rva: int, count: int = 64) -> list[dict[str, Any]]:
        """Linear listing at ``rva`` (for addresses outside discovered functions)."""
        s = self._get(sha)
        return [
            {
                "address": i.address,
                "bytes": i.raw.hex(),
                "text": i.text(),
                "mnemonic": i.mnemonic,
                "operands": i.op_str,
                "target": i.target,
                "comment": i.comment,
                "data_ref": i.data_ref,
            }
            for i in Disassembler(s.view()).linear(rva, min(count, 512))
        ]

    def read_bytes(self, sha: str, offset: int, length: int) -> dict[str, Any]:
        s = self._get(sha)
        offset = max(0, offset)
        chunk = s.data[offset : offset + min(max(0, length), MAX_READ)]
        return {"offset": offset, "data": base64.b64encode(chunk).decode(), "total": len(s.data)}

    # -- relations, search, symbols, memory map -----------------------------------------

    def _code_ready(self, s: _Sample) -> None:
        """Functions and xrefs exist only once the slow lane has finished."""
        if not s.pipeline.wait_slow(0):
            raise ApiError("analysis.not_ready")

    def _callgraph(self, s: _Sample) -> CallGraph:
        with self._lock:
            if s.callgraph is None:
                s.callgraph = CallGraph.build(s.functions, s.ctx.results.get("xrefs"))
            return s.callgraph

    def get_relations(
        self, sha: str, start: int, callers: int = 2, callees: int = 2
    ) -> dict[str, Any]:
        """The functions around ``start``: who calls it, what it calls, and the way in."""
        s = self._get(sha)
        self._code_ready(s)
        if start not in s.functions:
            raise ApiError(f"no function at {start:#x}")
        graph = self._callgraph(s)
        entry = s.report.entry_point if s.report is not None else 0
        export_names = (
            {rva: n for n, rva in sorted(s.report.export_rvas.items(), reverse=True)}
            if s.report
            else {}
        )
        exported = set(export_names)
        path = graph.path_to(start, {entry, *exported})
        hood = graph.neighbourhood(
            start,
            min(max(callers, 1), MAX_DEPTH),
            min(max(callees, 1), MAX_DEPTH),
            MAX_RELATION_NODES,
            keep=path,
        )
        scores = {r.start: r.score for r in s.ctx.results.get("ranking", [])}
        xrefs = s.ctx.results.get("xrefs")
        name_of = self._namer(s)
        return {
            "center": start,
            "nodes": [
                {
                    "start": n.start,
                    "name": name_of(n.start),
                    "role": n.role,
                    "distance": n.distance,
                    "score": scores.get(n.start, 0),
                    "apis": [
                        {"name": a.name, "family": a.family, "suspicious": a.suspicious}
                        for a in apis_of(xrefs, n.start)
                    ],
                    "is_entry": n.start == entry,
                    "is_export": n.start in exported,
                    "recursive": graph.recursive(n.start),
                    "hidden_callers": n.hidden_callers,
                    "hidden_callees": n.hidden_callees,
                }
                for n in hood.nodes
            ],
            "edges": [{"src": src, "dst": dst} for src, dst in hood.edges],
            "path": list(path),
            # what the path starts at: the program's entry point or an exported function
            "path_root": (
                None
                if not path
                else {"kind": "entry", "name": name_of(path[0])}
                if path[0] == entry
                else {"kind": "export", "name": export_names[path[0]]}
            ),
            "truncated": hood.truncated,
        }

    def _rva_of(self, s: _Sample, offset: int) -> int | None:
        """RVA of a file offset, or ``None`` for bytes no section maps (headers, overlay)."""
        if s.report is None:
            return offset if 0 <= offset < len(s.data) else None
        for sec in s.report.sections:
            delta = offset - sec.raw_offset
            # the loader maps SizeOfRawData when VirtualSize is 0 (hand-made and packed PEs)
            if sec.raw_size and 0 <= delta < min(sec.raw_size, sec.virtual_size or sec.raw_size):
                return sec.virtual_address + delta
        return None

    def search(self, sha: str, kind: str, query: str, limit: int = 500) -> dict[str, Any]:
        """Find bytes (``4D 5A ?? 00``), instruction text or an immediate value."""
        s = self._get(sha)
        limit = min(max(limit, 1), MAX_SEARCH_HITS)
        name_of = self._namer(s)
        index = s.ctx.index

        def row(rva: int | None, offset: int | None, fn: int | None, text: str) -> dict[str, Any]:
            return {
                "rva": rva,
                "offset": offset,
                "function": fn,
                "function_name": name_of(fn) if fn is not None else None,
                "text": text,
            }

        if kind == "bytes":
            try:
                pattern = search_mod.parse_pattern(query)
            except ValueError as exc:
                raise ApiError("search.bad_pattern") from exc
            offsets, truncated = search_mod.search_bytes(s.data, pattern, limit)
            rows = []
            for offset in offsets:
                rva = self._rva_of(s, offset)
                fn = index.lookup(rva) if index is not None and rva is not None else None
                found = s.data[offset : offset + min(len(pattern), 16)]
                rows.append(row(rva, offset, fn.start if fn else None, found.hex(" ")))
            return {"items": rows, "truncated": truncated}
        if kind not in ("text", "imm"):
            raise ApiError(f"unknown search kind {kind!r}")
        if kind == "imm":
            try:
                value = search_mod.parse_number(query)
            except ValueError as exc:
                raise ApiError("search.bad_number") from exc
        self._code_ready(s)
        if kind == "imm":
            hits, truncated = search_mod.search_immediate(s.functions, value, limit)
        else:
            hits, truncated = search_mod.search_text(s.functions, query, limit)
        return {
            "items": [
                row(h.address, self._offset_of(s, h.address), h.function, h.text) for h in hits
            ],
            "truncated": truncated,
        }

    def get_symbols(self, sha: str) -> dict[str, Any]:
        """Imports by DLL (with the number of places that reference each) and exports."""
        s = self._get(sha)
        r = s.report
        if r is None:
            return {"imports": [], "exports": []}
        xrefs = s.ctx.results.get("xrefs")
        index = s.ctx.index
        by_dll: dict[str, list[dict[str, Any]]] = {}
        for rva, full in r.import_addresses.items():
            dll, _, name = full.rpartition("!")
            refs = len(xrefs.to(rva)) if xrefs is not None else 0
            by_dll.setdefault(dll, []).append({"name": name, "rva": rva, "refs": refs})
        exports = []
        for name, rva in sorted(r.export_rvas.items())[:MAX_EXPORTS]:
            fn = index.lookup(rva) if index is not None else None
            exports.append({"name": name, "rva": rva, "function": fn.start if fn else None})
        return {
            "imports": [
                {"dll": dll, "functions": sorted(funcs, key=lambda f: f["name"].lower())}
                for dll, funcs in sorted(by_dll.items())
            ],
            "exports": exports,
        }

    def get_memory_map(self, sha: str) -> dict[str, Any]:
        """Headers, sections and overlay in file order; the sizes add up to the file size."""
        s = self._get(sha)
        with self._lock:
            if s.memory_map is None:
                s.memory_map = self._build_memory_map(s)
            return s.memory_map

    def _build_memory_map(self, s: _Sample) -> dict[str, Any]:
        total = len(s.data)
        r = s.report
        if r is None:
            assert s.raw is not None
            region = {
                "name": "raw",
                "kind": "raw",
                "rva": 0,
                "vsize": total,
                "offset": 0,
                "size": total,
                "perm": "RWX",
                "entropy": s.raw.entropy,
            }
            return {"size": total, "regions": [region]}
        regions: list[dict[str, Any]] = []
        cursor = 0

        def plain(name: str, kind: str, end: int) -> None:
            nonlocal cursor
            end = min(end, total)
            if end > cursor:
                chunk = s.data[cursor:end]
                regions.append(
                    {
                        "name": name,
                        "kind": kind,
                        "rva": None,
                        "vsize": 0,
                        "offset": cursor,
                        "size": len(chunk),
                        "perm": "---",
                        "entropy": round(shannon_entropy(chunk), 3),
                    }
                )
                cursor = end

        backed = sorted((x for x in r.sections if x.raw_size), key=lambda x: x.raw_offset)
        plain("headers", "headers", backed[0].raw_offset if backed else total)
        for sec in [*backed, *(x for x in r.sections if not x.raw_size)]:
            plain("gap", "gap", sec.raw_offset if sec.raw_size else cursor)
            end = min(sec.raw_offset + sec.raw_size, total) if sec.raw_size else cursor
            regions.append(
                {
                    "name": sec.name,
                    "kind": "section",
                    "rva": sec.virtual_address,
                    "vsize": sec.virtual_size,
                    "offset": cursor,
                    "size": max(0, end - cursor),  # bytes not already counted
                    "perm": _perm(sec.readable, sec.writable, sec.executable),
                    "entropy": sec.entropy,
                }
            )
            cursor = max(cursor, end)
        if r.overlay_offset is not None and r.overlay_size:
            plain("gap", "gap", r.overlay_offset)
            plain("overlay", "overlay", total)
        plain("gap", "gap", total)
        return {"size": total, "regions": regions}

    # -- AI analyst ------------------------------------------------------------------------

    def ai_status(self) -> dict[str, Any]:
        """Where a request would go. Never includes the key."""
        found = ai_client.endpoints(self._config.ai)
        return {
            "configured": bool(found),
            "endpoints": [
                {"host": e.host, "model": e.model, "local": e.local, "has_key": e.key is not None}
                for e in found
            ],
        }

    def _ai_code(self, s: _Sample, start: int, ahash: str) -> tuple[str | None, Any]:
        """Pseudo-C if it is already cached (Ghidra is never started for this), else assembly."""
        if s.ghidra_version is not None:
            cached = self._decomp_cached(s, ahash, start, start)
            if cached is not None:
                return "\n".join(line.text for line in cached.lines), "pseudo_c"
        fn = s.functions.get(start)
        if fn is None:
            return None, None
        lines: list[str] = []
        for block_start in sorted(fn.blocks):
            for insn in fn.blocks[block_start].instructions:
                if len(lines) >= AI_ASM_LINES:
                    lines.append("…")
                    return "\n".join(lines), "asm"
                lines.append(f"{insn.address:x}  {insn.text()}")
        return ("\n".join(lines), "asm") if lines else (None, None)

    def _ai_bundle(self, s: _Sample) -> Bundle:
        """The evidence the AI analyst would get right now (analysis results only)."""
        self._code_ready(s)
        verdicts = self._verdicts(s)
        facts = [f for f in list(s.ctx.facts) if verdicts.get(f.id) not in IGNORED_VERDICTS]
        score = risk_score(facts, verdicts)
        graph = self._callgraph(s)
        xrefs = s.ctx.results.get("xrefs")
        name_of = self._namer(s)
        names, comments = self._decomp_annotations(s)
        ahash = annotation_hash(names, comments)
        string_at = {x.rva: x.value for x in s.ctx.results.get("strings", []) if x.rva is not None}
        ranking = {r.start: r for r in s.ctx.results.get("ranking", [])}
        r = s.report
        entry = r.entry_point if r is not None and r.entry_point in s.functions else None
        starts = [fn.start for fn in sorted(ranking.values(), key=lambda x: -x.score)]
        if not starts and entry is None:  # nothing ranked: describe the first functions
            starts = sorted(s.functions)[:AI_FUNCTIONS]
        ordered = list(
            dict.fromkeys(starts[:AI_FUNCTIONS] + ([entry] if entry is not None else []))
        )
        functions = []
        for start in ordered:
            ranked = ranking.get(start)
            refs = xrefs.from_function(start) if xrefs is not None else []
            code, kind = self._ai_code(s, start, ahash)
            functions.append(
                FunctionEvidence(
                    start=start,
                    name=name_of(start),
                    score=ranked.score if ranked else 0,
                    reasons=ranked.reasons if ranked else (),
                    apis=[(a.name, a.family) for a in apis_of(xrefs, start)],
                    callers=[(c, name_of(c)) for c in graph.callers(start)],
                    callees=[(c, name_of(c)) for c in graph.callees(start)],
                    strings=list(
                        dict.fromkeys(string_at[x.dst] for x in refs if x.dst in string_at)
                    ),
                    code=code,
                    code_kind=kind,
                )
            )
        family_of = {api: fam for fam, apis in API_FAMILIES.items() for api in apis}
        imports: dict[str, list[str]] = {}
        for full in sorted(set(r.import_addresses.values())) if r is not None else []:
            api = normalize_api(full.rpartition("!")[2])
            family = family_of.get(api)
            if family in SUSPICIOUS_FAMILIES and api not in imports.setdefault(family, []):
                imports[family].append(api)
        packer = s.ctx.results.get("packer")
        notes = [(a, "name", v) for a, v in sorted(names.items())]
        notes += [(a, "comment", v) for a, v in sorted(comments.items())]
        data = BundleInput(
            name=s.path.name,
            sha256=s.sha,
            size=len(s.data),
            format="pe" if r is not None else "raw",
            bits=s.ctx.bits,
            is_dll=bool(r is not None and r.is_dll),
            entry_point=r.entry_point if r is not None else None,
            compile_time=r.compile_time.isoformat() if r is not None else None,
            signature=(
                "none"
                if r is None or not r.signature.present
                else "verified"
                if r.signature.verified
                else "present, not verified"
            ),
            packer=(packer.packer or "unknown packer") if packer and packer.packed else None,
            score=score.score,
            band=score.band,
            facts=facts,
            functions=functions,
            iocs=[
                (i.type, i.value) for i in s.ctx.results.get("iocs", []) if i.benign_hint is None
            ],
            imports=imports,
            sections=(
                [
                    (x.name, _perm(x.readable, x.writable, x.executable), x.entropy)
                    for x in r.sections
                ]
                if r is not None
                else []
            ),
            notes=notes,
        )
        return build_bundle(data, self._config.ai.max_chars)

    def ai_preview(self, sha: str) -> dict[str, Any]:
        """Exactly what would be sent, and the destinations to choose from. Sends nothing."""
        bundle = self._ai_bundle(self._get(sha))
        found = ai_client.endpoints(self._config.ai)
        first = found[0] if found else None
        return {
            "text": bundle.text,
            "chars": len(bundle.text),
            "hash": bundle.hash,
            "omitted": bundle.omitted,
            "host": first.host if first else None,
            "model": first.model if first else None,
            "local": first.local if first else None,
            "endpoints": [{"host": e.host, "model": e.model, "local": e.local} for e in found],
        }

    def _ai_cache(self, s: _Sample, bundle: Bundle, model: str) -> Path:
        return ext_cache.cache_file(self._cache_dir, s.sha, "ai", model, bundle.hash)

    def _ai_last(self, s: _Sample) -> Path:
        """The newest report of a sample: kept when the evidence moves on (shown as stale)."""
        return ext_cache.cache_file(self._cache_dir, s.sha, "ai", "last", None)

    def ai_analyse(
        self, sha: str, confirmed_hash: str, force: bool = False, endpoint: int = 0
    ) -> None:
        """Send the evidence the analyst just confirmed (by its hash) to the chosen endpoint.

        The confirmation is for one send of one bundle to one destination: if the evidence
        changed since the preview nothing is sent, and a failed endpoint never falls back to
        another one by itself.
        """
        s = self._get(sha)
        bundle = self._ai_bundle(s)
        if not confirmed_hash or confirmed_hash != bundle.hash:
            raise ApiError("ai.preview_changed")
        found = ai_client.endpoints(self._config.ai)
        if isinstance(endpoint, bool) or not 0 <= endpoint < len(found):
            raise ApiError("ai.no_endpoint")
        target = found[endpoint]
        path = self._ai_cache(s, bundle, target.model)
        cached = None if force else ext_cache.load(path)
        if cached is not None:
            with contextlib.suppress(OSError):
                ext_cache.store(self._ai_last(s), cached)
            s.pipeline.set_state("ai", "done", cached=True)
            return
        with self._lock:
            if s.ai_running:
                return
            s.ai_running = True
        s.pipeline.set_state("ai", "running")
        lang = str(self._settings["language"])
        threading.Thread(
            target=self._ai_job, args=(s, bundle, target, path, lang), daemon=True, name="octov-ai"
        ).start()

    def _ai_job(
        self, s: _Sample, bundle: Bundle, target: ai_client.Endpoint, path: Path, lang: str
    ) -> None:
        """Always ends in ``done`` or ``failed`` (or drops the answer if the sample closed)."""
        start = time.monotonic()
        try:
            text = ai_client.chat(
                target, system_prompt(lang), bundle.text, float(self._config.ai.timeout_s)
            )
            report = parse_report(text, bundle)
            doc = report.to_dict() | {
                "model": target.model,
                "host": target.host,
                "local": target.local,
                "created": int(time.time()),
                "bundle_hash": bundle.hash,
                "omitted": bundle.omitted,
            }
            with contextlib.suppress(OSError):  # an unwritable cache only costs a new request
                ext_cache.store(path, doc)
                ext_cache.store(self._ai_last(s), doc)
            state: tuple[AnalyzerStatus, str | None] = ("done", None)
        except AIError as exc:
            state = ("failed", f"ai.{exc.kind}")  # the kind only: never a server's own text
        except Exception:  # a bug here must not leave the job "running"
            state = ("failed", "ai.internal")
        finally:
            s.ai_running = False
        if self._samples.get(s.sha) is s:
            s.pipeline.set_state("ai", state[0], state[1], elapsed_s=_secs(start))

    def get_ai_report(self, sha: str) -> dict[str, Any] | None:
        """The newest AI report of the sample; ``stale`` when the evidence changed since.

        Background engines (capa, FLOSS, Ghidra) and the analyst's own edits change the
        evidence; the opinion that was already paid for stays visible, labelled.
        """
        s = self._get(sha)
        doc = ext_cache.load(self._ai_last(s))
        if doc is None:
            return None
        stale = s.pipeline.wait_slow(0) and self._ai_bundle(s).hash != doc.get("bundle_hash")
        return doc | {"stale": bool(stale)}

    # -- exports ---------------------------------------------------------------------

    def _kept_findings(self, s: _Sample) -> list[Any]:
        """Rule findings minus those the analyst marked false positive / benign."""
        verdicts = self._verdicts(s)
        return [
            f
            for f in s.analysis.findings
            if verdicts.get(facts_from_findings([f])[0].id) not in IGNORED_VERDICTS
        ]

    def export_yara(self, sha: str) -> str:
        s = self._get(sha)
        target: PEReport | RawSample | None = s.report if s.report is not None else s.raw
        assert target is not None
        return generate_yara(target, self._kept_findings(s))

    def export_sigma(self, sha: str) -> str | None:
        s = self._get(sha)
        if s.report is None:
            return None
        verdicts = self._verdicts(s)
        indicators = [
            ind
            for ind, fact in zip(s.report.indicators, facts_from_indicators(s.report), strict=True)
            if verdicts.get(fact.id) not in IGNORED_VERDICTS
        ]
        return generate_sigma(s.report, self._kept_findings(s), indicators)

    # -- optional engines (capa, FLOSS) ------------------------------------------------

    def get_extensions(self) -> list[dict[str, Any]]:
        auto = self._settings["extensions_auto_run"]
        statuses = [*extension_status(self._rules_root), ghidra_status(self._config.ghidra)]
        return [st.to_dict() | {"auto_run": auto[st.id]} for st in statuses]

    def run_extension(self, sha: str, ext_id: str, force: bool = False) -> None:
        if ext_id == "ghidra":
            self._schedule_ghidra(self._get(sha), explicit=True, force=force)
            return
        if ext_id not in ENGINES:
            raise ApiError(f"unknown extension {ext_id!r}")
        self._schedule_extensions(self._get(sha), only=ext_id, explicit=True, force=force)

    def _schedule_extensions(
        self,
        s: _Sample,
        only: str | None = None,
        explicit: bool = False,
        force: bool = False,
    ) -> None:
        for st in extension_status(self._rules_root):
            if only is not None and st.id != only:
                continue
            reason = self._unavailable_reason(s, st)
            if reason is not None:
                s.pipeline.set_state(st.id, "unavailable", reason)
                continue
            path = ext_cache.cache_file(
                self._cache_dir, s.sha, st.id, st.version or "?", st.rules_version
            )
            doc = None if force else ext_cache.load(path)
            if doc is not None:
                s.pipeline.set_state(st.id, "running")
                threading.Thread(
                    target=self._finish_engine,
                    args=(s, st.id, doc, None, True, None),
                    daemon=True,
                    name=f"octov-{st.id}-cached",
                ).start()
                continue
            if not explicit and not self._settings["extensions_auto_run"][st.id]:
                s.pipeline.set_state(st.id, "idle")
                continue
            before = s.pipeline.status().get(st.id)
            s.pipeline.set_state(st.id, "queued")
            accepted = QUEUES[st.id].submit(s.sha, self._engine_job(s, st, path), owner=s)
            if not accepted and before is not None:
                # already queued or running for this very sample: keep its real state
                s.pipeline.set_state(
                    st.id,
                    before["state"],
                    before["error"],
                    elapsed_s=before["elapsed_s"],
                    cached=before["cached"],
                )

    def _unavailable_reason(self, s: _Sample, st: ExtensionStatus) -> str | None:
        if not st.ready:
            return st.reason_key or "ext.reason.not_installed"
        if s.parent is not None or not s.path.is_file():
            return "ext.reason.in_memory"
        if len(s.data) > self._config.extensions[st.id].max_size_mb * 1024 * 1024:
            return "ext.reason.too_large"
        return None

    def _engine_command(self, s: _Sample, st: ExtensionStatus) -> list[str]:
        raw = s.report is None
        if st.id == "floss":
            return floss_ext.floss_command(s.path, raw=raw, bits=s.ctx.bits)
        rules = capa_rules_dir(self._rules_root)
        if rules is None:
            raise EngineError("crash", "capa rules missing")
        sigs = capa_sigs_dir(self._sigs_root, rules[0])
        if sigs is None:  # run without library recognition rather than not at all
            sigs = self._cache_dir / "empty-sigs"
            sigs.mkdir(parents=True, exist_ok=True)
        return capa_ext.capa_command(s.path, rules[1], sigs, raw=raw, bits=s.ctx.bits)

    def _file_unchanged(self, s: _Sample) -> bool:
        """Engines read the file from disk: it must still be the bytes that were opened."""
        try:
            return hashlib.sha256(s.path.read_bytes()).hexdigest() == s.sha
        except OSError:
            return False

    def _engine_job(self, s: _Sample, st: ExtensionStatus, cache_path: Path) -> Any:
        limits = self._config.extensions[st.id]

        def job(cancel: threading.Event) -> None:
            if self._samples.get(s.sha) is not s:
                return  # closed while queued
            s.pipeline.set_state(st.id, "running")
            start = time.monotonic()
            try:
                if not self._file_unchanged(s):
                    raise EngineError("crash", "file changed on disk")
                run = run_engine(
                    self._engine_command(s, st),
                    timeout_s=limits.timeout_s,
                    max_memory_mb=limits.max_memory_mb,
                    cancel=cancel,
                )
                doc = parse_json(run)
                if not self._file_unchanged(s):
                    raise EngineError("crash", "file changed on disk")
            except EngineError as exc:
                s.pipeline.set_state(st.id, "failed", exc.reason, elapsed_s=_secs(start))
                return
            except Exception as exc:  # every job must end in a terminal state
                s.pipeline.set_state(st.id, "failed", f"internal error: {exc}")
                return
            if st.id == "capa" and not s.pipeline.wait_slow(0):
                # capa attaches to discovered functions: wait for the slow lane, but not
                # inside the engine queue, which would hold up every other sample's capa run
                threading.Thread(
                    target=self._finish_engine,
                    args=(s, st.id, doc, cache_path, False, _secs(start)),
                    daemon=True,
                    name="octov-capa-apply",
                ).start()
                return
            self._finish_engine(s, st.id, doc, cache_path, False, _secs(start))

        return job

    def _finish_engine(
        self,
        s: _Sample,
        engine: str,
        doc: dict[str, Any],
        cache_path: Path | None,
        cached: bool,
        elapsed: float | None,
    ) -> None:
        """Apply an engine result; always ends in ``done`` or ``failed`` (or drops it if closed)."""
        try:
            if engine == "capa":
                while not s.pipeline.wait_slow(0.5):
                    if self._samples.get(s.sha) is not s:
                        return  # closed while waiting
            if self._samples.get(s.sha) is not s:
                return  # closed meanwhile: drop the result
            (apply_capa if engine == "capa" else apply_floss)(s.ctx, s.pipeline, doc)
        except EngineError as exc:
            s.pipeline.set_state(engine, "failed", exc.reason, elapsed_s=elapsed)
            return
        except Exception as exc:  # an adapter bug must not leave the job "running"
            s.pipeline.set_state(engine, "failed", f"internal error: {exc}", elapsed_s=elapsed)
            return
        if cache_path is not None:
            # a cache that cannot be written only costs a rerun next time
            with contextlib.suppress(OSError):
                ext_cache.store(cache_path, doc)
        s.pipeline.set_state(engine, "done", elapsed_s=elapsed, cached=cached)

    # -- decompiler (Ghidra worker) -----------------------------------------------------

    def _schedule_ghidra(self, s: _Sample, explicit: bool = False, force: bool = False) -> None:
        """Queue the sample for its Ghidra worker (never blocks: analysis is in the background)."""
        st = ghidra_status(self._config.ghidra)
        if not st.ready:
            reason = st.reason_key or "ext.reason.not_installed"
            s.pipeline.set_state("ghidra", "unavailable", reason)
            return
        if s.report is None:
            s.pipeline.set_state("ghidra", "unavailable", "ext.reason.pe_only")
            return
        s.ghidra_version = st.version or "?"
        if not explicit and not self._settings["extensions_auto_run"]["ghidra"]:
            s.pipeline.set_state("ghidra", "idle")
            return
        self._start_ghidra_housekeeping()
        if force:
            self._ghidra.close(s.sha)
            shutil.rmtree(self._ghidra_root / s.sha, ignore_errors=True)

        def on_state(state: str, error: str | None, elapsed_s: float) -> None:
            if self._samples.get(s.sha) is not s:
                return  # closed meanwhile
            ended = state in ("done", "failed")
            s.pipeline.set_state(
                "ghidra",
                cast(AnalyzerStatus, state),
                error,
                elapsed_s=round(elapsed_s, 1) if ended else None,
            )
            if state == "done":
                threading.Thread(
                    target=self._predecompile, args=(s,), daemon=True, name="octov-ghidra-ahead"
                ).start()

        self._ghidra.ensure(s.sha, s.data, on_state)

    def _start_ghidra_housekeeping(self) -> None:
        """First use only: drop long-unused projects, then stop idle workers now and then."""
        with self._lock:
            if self._ghidra_started:
                return
            self._ghidra_started = True
        cleanup_projects(self._ghidra_root, self._config.ghidra.project_keep_days, time.time())

        def reap() -> None:
            while not self._ghidra_stop.wait(_REAP_EVERY_S):
                self._ghidra.reap_idle()

        threading.Thread(target=reap, daemon=True, name="octov-ghidra-idle").start()

    def shutdown(self) -> None:
        """App exit: stop every Ghidra worker (the Job Object would kill them anyway)."""
        self._ghidra_stop.set()
        self._ghidra.shutdown_all()

    def _predecompile(self, s: _Sample) -> None:
        """Entry point and top-ranked functions go into the cache before anyone asks."""
        while not s.pipeline.wait_slow(0.5):
            if self._samples.get(s.sha) is not s:
                return
        starts = [s.report.entry_point] if s.report is not None else []
        starts += [fn.start for fn in s.ctx.results.get("ranking", [])[:PREDECOMPILE]]
        for start in dict.fromkeys(starts):
            if self._samples.get(s.sha) is not s:
                return
            try:
                self.get_decompiled(s.sha, start)
            except ApiError:
                if s.pipeline.status().get("ghidra", {}).get("state") != "done":
                    return  # the worker is gone: nothing more to do ahead of time

    def _decomp_annotations(self, s: _Sample) -> tuple[dict[int, str], dict[int, str]]:
        """Analyst names and comments by address: what changes the pseudo-C text."""
        names = self._names(s)[0]
        comments = {
            a.address: a.value for a in self._annotations(s, "comment") if a.address is not None
        }
        return names, comments

    def _decomp_cached(
        self, s: _Sample, ahash: str, rva: int, octov_start: int | None
    ) -> DecompiledFunction | None:
        for entry in dict.fromkeys((s.decomp_entries.get(rva), rva, octov_start)):
            if entry is None:
                continue
            path = decomp_cache_path(self._cache_dir, s.sha, s.ghidra_version or "?", ahash, entry)
            doc = ext_cache.load(path)
            fn = DecompiledFunction.from_dict(doc) if doc is not None else None
            if fn is not None and (
                fn.entry_rva == rva
                or s.decomp_entries.get(rva) == fn.entry_rva
                or any(rva in line.rvas for line in fn.lines)
            ):
                return fn
        return None

    def get_decompiled(self, sha: str, rva: int) -> dict[str, Any]:
        """Pseudo-C of the Ghidra function containing ``rva``, with per-line marks."""
        s = self._get(sha)
        job = s.pipeline.status().get("ghidra")
        if job is None:
            raise ApiError("decomp.not_ready")
        if job["state"] == "unavailable":
            raise ApiError(job["error"] or "decomp.not_ready")
        octov_fn = s.ctx.index.lookup(rva) if s.ctx.index is not None else None
        octov_start = octov_fn.start if octov_fn is not None else None
        version = s.ghidra_version or "?"
        fn: DecompiledFunction | None = None
        cached = False
        for _attempt in range(_DECOMP_ATTEMPTS):
            names, comments = self._decomp_annotations(s)
            ahash = annotation_hash(names, comments)
            hit = self._decomp_cached(s, ahash, rva, octov_start)
            if hit is not None:
                fn, cached = hit, True
                break
            state = s.pipeline.status()["ghidra"]["state"]
            if state != "done":
                analysing = state in ("queued", "running")
                raise ApiError("decomp.analysing" if analysing else "decomp.not_ready")
            try:
                fn = DecompiledFunction.from_reply(
                    self._ghidra.decompile(sha, rva, names, comments)
                )
            except GhidraError as exc:
                raise ApiError(_decomp_error(exc)) from exc
            s.decomp_entries[rva] = fn.entry_rva
            path = decomp_cache_path(self._cache_dir, sha, version, ahash, fn.entry_rva)
            with contextlib.suppress(OSError):  # an unwritable cache only costs a rerun
                ext_cache.store(path, fn.to_dict())
            if annotation_hash(*self._decomp_annotations(s)) == ahash:
                break  # else: renamed while Ghidra was answering; that text is already stale
        assert fn is not None
        verdicts = self._verdicts(s)
        facts = [f for f in list(s.ctx.facts) if verdicts.get(f.id) not in IGNORED_VERDICTS]
        out = fn.to_dict()
        for line, marks in zip(out["lines"], line_marks(fn, facts, suspicious_apis()), strict=True):
            line["marks"] = marks
        return out | {"octov_function": octov_start, "cached": cached}

    # -- sessions --------------------------------------------------------------------

    def new_session(self, path: str) -> dict[str, Any]:
        try:
            session = Session.create(path)
        except (SessionError, OSError) as exc:
            raise ApiError(str(exc)) from exc
        self._attach(session)
        with self._lock:
            for s in self._samples.values():
                self._persist(session, s)
                self._merge_workspace(session, s)
        return {"path": str(session.path)}

    def open_session(self, path: str) -> list[dict[str, Any]]:
        try:
            session = Session.open(path)
        except SessionError as exc:
            raise ApiError(str(exc)) from exc
        self._attach(session)
        opened = []
        for row in session.list_samples():
            stored = session.get_sample(row.sha256) or {}
            if row.path and Path(row.path).is_file():
                raw = stored.get("format") == "raw"
                summary = self.open_sample(row.path, raw=raw, bits=int(stored.get("bits", 64)))
                opened.append(summary)
        return opened

    def close_session(self) -> None:
        self._attach(None)

    def _attach(self, session: Session | None) -> None:
        with self._lock:
            if self._session is not None:
                self._session.commit()
                self._session.close()
            self._session = session


def _decomp_error(exc: GhidraError) -> str:
    """UI message key (the web UI translates it; a detail follows after ``": "``)."""
    if exc.kind in ("no_function", "timeout", "not_ready"):
        return f"decomp.{exc.kind}"
    return f"decomp.failed: {exc.reason}"


def _secs(start: float) -> float:
    return round(time.monotonic() - start, 1)
