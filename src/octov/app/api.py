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
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from octov.core.analysis.analyzers import default_analyzers
from octov.core.analysis.carve import payload_zip
from octov.core.analysis.facts import Fact, facts_from_findings
from octov.core.analysis.iocs import iocs_csv, iocs_json
from octov.core.analysis.pipeline import AnalysisContext, Pipeline
from octov.core.analysis.report import build_triage
from octov.core.analysis.scoring import IGNORED_VERDICTS
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
from octov.core.static.pe_parser import Hashes, PEParseError, PEReport
from octov.core.static.rules import Rule, RuleError

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
MAX_READ = 1 << 20  # largest hex chunk a single call may return
MAX_STRINGS_PAGE = 2000
VERDICTS = ("false_positive", "benign", "confirmed")


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
    ) -> None:
        self._config = config or Config()
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

    # -- settings & strings ------------------------------------------------------

    def _load_settings(self) -> dict[str, str]:
        settings = {"language": self._config.ui.language, "theme": self._config.ui.theme}
        try:
            stored = json.loads(self._settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return settings
        if stored.get("language") in LANGUAGES:
            settings["language"] = stored["language"]
        if stored.get("theme") in THEMES:
            settings["theme"] = stored["theme"]
        return settings

    def get_settings(self) -> dict[str, str]:
        return dict(self._settings)

    def set_settings(self, settings: dict[str, str]) -> dict[str, str]:
        lang = settings.get("language", self._settings["language"])
        theme = settings.get("theme", self._settings["theme"])
        if lang not in LANGUAGES or theme not in THEMES:
            raise ApiError(f"invalid settings: {settings}")
        self._settings = {"language": lang, "theme": theme}
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
            self._samples[sha] = sample
            if self._session is not None:
                self._persist(self._session, sample)
            else:
                ws = self._workspace_dir / f"{sha}.octov"
                if ws.is_file():
                    try:
                        sample.store = Session.open(ws)
                    except SessionError:
                        sample.store = None
        pipeline.start_slow(ctx)
        return self._summary(sample)

    def _persist(self, session: Session, sample: _Sample) -> None:
        try:
            session.add_sample(sample.analysis)
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
        with self._lock:
            sample = self._samples.pop(sha, None)
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
    ) -> dict[str, Any]:
        s = self._get(sha)
        items = list(s.ctx.results.get("strings", []))
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
                    "xrefs": len(xrefs.to(x.rva))
                    if xrefs is not None and x.rva is not None
                    else None,
                }
                for x in page
            ],
        }

    def get_iocs(self, sha: str) -> list[dict[str, Any]]:
        return list(self.get_triage(sha)["iocs"])

    def export_iocs(self, sha: str, fmt: str = "csv") -> str:
        iocs = self._get(sha).ctx.results.get("iocs", [])
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
        out = []
        for start, fn in sorted(s.functions.items()):
            name = own.get(start) or exports.get(start) or suggested.get(start) or f"sub_{start:x}"
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
        return generate_sigma(s.report, self._kept_findings(s))

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
