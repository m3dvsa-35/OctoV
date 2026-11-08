"""WorkbenchApi: the contract between the web UI and the Python analysis core.

Every public method takes and returns JSON-serialisable values. The same object
is exposed to the desktop window through pywebview's JS bridge (no network) and,
for development, through the token-protected loopback server in ``devserver``.
Methods may be called from several threads; shared state is guarded by a lock.
"""

from __future__ import annotations

import base64
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from octov.core.config import THEMES, Config
from octov.core.export.sigma_gen import generate_sigma
from octov.core.export.yara_gen import generate_yara
from octov.core.i18n import LANGUAGES
from octov.core.mitre import technique_name, technique_tactic
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
from octov.core.static.cfg import Function, FunctionIndex, discover_from, discover_functions
from octov.core.static.disasm import Disassembler, ImageView, RawView
from octov.core.static.pe_parser import Hashes, PEParseError, PEReport
from octov.core.static.rules import Finding, Rule, RuleError

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
MAX_READ = 1 << 20  # largest hex chunk a single call may return


class ApiError(Exception):
    """User-facing error; the message is shown in the UI."""


@dataclass
class _Sample:
    path: Path
    data: bytes
    analysis: StaticAnalysis | RawAnalysis
    status: str = "running"
    error: str | None = None
    functions: dict[int, Function] = field(default_factory=dict)
    index: FunctionIndex | None = None

    @property
    def sha(self) -> str:
        return self.hashes.sha256

    @property
    def hashes(self) -> Hashes:
        if isinstance(self.analysis, StaticAnalysis):
            return self.analysis.report.hashes
        return self.analysis.sample.hashes

    @property
    def report(self) -> PEReport | None:
        return self.analysis.report if isinstance(self.analysis, StaticAnalysis) else None

    @property
    def raw(self) -> RawSample | None:
        return self.analysis.sample if isinstance(self.analysis, RawAnalysis) else None

    def view(self) -> ImageView | RawView:
        if self.report is not None:
            return ImageView(self.data, self.report)
        assert self.raw is not None
        return RawView(self.data, bits=self.raw.bits)


def _perm(readable: bool, writable: bool, executable: bool) -> str:
    return ("R" if readable else "-") + ("W" if writable else "-") + ("X" if executable else "-")


class WorkbenchApi:
    def __init__(self, config: Config | None = None, settings_path: Path | None = None) -> None:
        self._config = config or Config()
        self._settings_path = settings_path or Path.home() / ".octov" / "ui.json"
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
        limit = self._config.static.max_file_size_mb * 1024 * 1024
        if len(data) > limit:
            raise ApiError(f"file exceeds {self._config.static.max_file_size_mb} MB limit")
        try:
            analysis: StaticAnalysis | RawAnalysis
            if raw:
                raw_result = analyze_raw(data, self._rules, bits=bits)
                raw_result.sample.path = str(file)
                analysis = raw_result
            else:
                pe_result = analyze(data, self._rules)
                pe_result.report.path = str(file)
                analysis = pe_result
        except PEParseError as exc:
            raise ApiError(f"{exc} - open it as a raw code blob instead") from exc
        except ValueError as exc:
            raise ApiError(str(exc)) from exc

        sample = _Sample(file, data, analysis)
        with self._lock:
            existing = self._samples.get(sample.sha)
            if existing is not None and existing.status != "failed":
                return self._summary(existing)
            self._samples[sample.sha] = sample
            if self._session is not None:
                try:
                    self._session.add_sample(analysis)
                    self._session.commit()
                except SessionError as exc:
                    raise ApiError(str(exc)) from exc
        threading.Thread(target=self._discover, args=(sample,), daemon=True).start()
        return self._summary(sample)

    def _discover(self, sample: _Sample) -> None:
        try:
            dis = Disassembler(sample.view())
            if sample.report is not None:
                functions = discover_functions(dis, sample.report)
            else:
                functions = discover_from(dis, [0])
            index = FunctionIndex(functions)
        except Exception as exc:  # surfaced through discovery_status
            with self._lock:
                sample.status, sample.error = "failed", str(exc)
            return
        with self._lock:
            sample.functions, sample.index, sample.status = functions, index, "done"

    def _get(self, sha: str) -> _Sample:
        with self._lock:
            sample = self._samples.get(sha)
        if sample is None:
            raise ApiError(f"unknown sample {sha[:12]}")
        return sample

    def _summary(self, s: _Sample) -> dict[str, Any]:
        counts = {k: 0 for k in _SEVERITY_ORDER}
        for row in self._finding_rows(s):
            counts[row["severity"]] += 1
        return {
            "sha256": s.sha,
            "name": s.path.name,
            "path": str(s.path),
            "format": "pe" if s.report is not None else "raw",
            "size": len(s.data),
            "counts": counts,
        }

    def list_samples(self) -> list[dict[str, Any]]:
        with self._lock:
            samples = list(self._samples.values())
        return [self._summary(s) for s in samples]

    def close_sample(self, sha: str) -> None:
        with self._lock:
            self._samples.pop(sha, None)

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

    # -- findings --------------------------------------------------------------------

    def _finding_rows(self, s: _Sample) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if s.report is not None:
            for ind in s.report.indicators:
                rows.append(
                    {
                        "id": ind.id,
                        "kind": "indicator",
                        "name": ind.id.replace("_", " "),
                        "severity": ind.severity,
                        "mitre": ind.mitre,
                        "description": ind.description,
                        "rva": None,
                        "offset": ind.evidence.get("offset") or ind.evidence.get("raw_offset"),
                        "evidence": [{"detail": json.dumps(ind.evidence, default=str)}],
                    }
                )
        for f in s.analysis.findings:
            rows.append(self._rule_row(f))
        for row in rows:
            row["mitre_names"] = {t: technique_name(t) for t in row["mitre"]}
        rows.sort(key=lambda r: (_SEVERITY_ORDER[r["severity"]], r["id"]))
        return rows

    @staticmethod
    def _rule_row(f: Finding) -> dict[str, Any]:
        located = next((m for m in f.matches if m.rva is not None or m.offset is not None), None)
        return {
            "id": f.rule_id,
            "kind": "rule",
            "name": f.name,
            "severity": f.severity,
            "mitre": f.mitre,
            "description": f.description,
            "rva": located.rva if located else None,
            "offset": located.offset if located else None,
            "evidence": [
                {
                    "type": m.type,
                    "value": m.value,
                    "detail": m.detail,
                    "offset": m.offset,
                    "rva": m.rva,
                }
                for m in f.matches
            ],
        }

    def get_findings(self, sha: str) -> list[dict[str, Any]]:
        return self._finding_rows(self._get(sha))

    def get_mitre(self, sha: str) -> list[dict[str, Any]]:
        agg: dict[str, dict[str, Any]] = {}
        for row in self.get_findings(sha):
            for t in row["mitre"]:
                entry = agg.setdefault(
                    t,
                    {
                        "technique": t,
                        "name": technique_name(t),
                        "tactic": technique_tactic(t),
                        "severity": "info",
                        "sources": [],
                    },
                )
                if _SEVERITY_ORDER[row["severity"]] < _SEVERITY_ORDER[entry["severity"]]:
                    entry["severity"] = row["severity"]
                if row["id"] not in entry["sources"]:
                    entry["sources"].append(row["id"])
        for entry in agg.values():
            entry["hits"] = len(entry["sources"])
        return sorted(
            agg.values(),
            key=lambda e: (_SEVERITY_ORDER[e["severity"]], -e["hits"], e["technique"]),
        )

    # -- code ------------------------------------------------------------------------

    def discovery_status(self, sha: str) -> dict[str, Any]:
        s = self._get(sha)
        with self._lock:
            return {"state": s.status, "functions": len(s.functions), "error": s.error}

    def _function_name(self, s: _Sample, start: int) -> str:
        if s.report is not None:
            for name, rva in s.report.export_rvas.items():
                if rva == start:
                    return name
        return f"sub_{start:x}"

    def list_functions(self, sha: str) -> list[dict[str, Any]]:
        s = self._get(sha)
        entry = s.report.entry_point if s.report is not None else 0
        return [
            {
                "start": start,
                "name": self._function_name(s, start),
                "blocks": len(fn.blocks),
                "size": fn.size,
                "is_entry": start == entry,
            }
            for start, fn in sorted(s.functions.items())
        ]

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
        data["name"] = self._function_name(s, start)
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
        fn = s.index.lookup(rva) if s.index is not None else None
        return {"rva": rva, "offset": self._offset_of(s, rva), "function": fn.start if fn else None}

    def disassemble(self, sha: str, rva: int, count: int = 64) -> list[dict[str, Any]]:
        """Linear listing at ``rva`` (for addresses outside discovered functions)."""
        s = self._get(sha)
        view = s.view()
        return [
            {
                "address": i.address,
                "bytes": i.raw.hex(),
                "text": i.text(),
                "mnemonic": i.mnemonic,
                "operands": i.op_str,
                "target": i.target,
                "comment": i.comment,
            }
            for i in Disassembler(view).linear(rva, min(count, 512))
        ]

    def read_bytes(self, sha: str, offset: int, length: int) -> dict[str, Any]:
        s = self._get(sha)
        offset = max(0, offset)
        chunk = s.data[offset : offset + min(max(0, length), MAX_READ)]
        return {"offset": offset, "data": base64.b64encode(chunk).decode(), "total": len(s.data)}

    # -- exports ---------------------------------------------------------------------

    def export_yara(self, sha: str) -> str:
        s = self._get(sha)
        target: PEReport | RawSample | None = s.report if s.report is not None else s.raw
        assert target is not None
        return generate_yara(target, s.analysis.findings)

    def export_sigma(self, sha: str) -> str | None:
        s = self._get(sha)
        if s.report is None:
            return None
        return generate_sigma(s.report, s.analysis.findings)

    # -- sessions --------------------------------------------------------------------

    def new_session(self, path: str) -> dict[str, Any]:
        try:
            session = Session.create(path)
        except (SessionError, OSError) as exc:
            raise ApiError(str(exc)) from exc
        self._attach(session)
        with self._lock:
            for s in self._samples.values():
                session.add_sample(s.analysis)
            session.commit()
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
