"""Read models for the dashboard: plain, detached rows, so a view never holds a database session.

Every function opens its own session and returns frozen dataclasses. Values
that came from a scanned repository (messages, paths, rule ids, snippets) are
returned exactly as stored -- already redacted -- and must be rendered as
literal text, never as Markdown (``dashboard/safe.py``).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select

from app.db.models import (Finding, LifecycleEvent, LifecycleState, Project, Scan, ScannerRun, TrackedFinding,
                           Verification)
from app.db.session import session_scope
from app.intelligence.lifecycle import OPEN_STATES
from app.mapping.mapper import owasp_label
from app.normalization.finding import SEVERITIES

STATES = tuple(s.value for s in LifecycleState)
TRANSITIONS = ("NEW", "STILL_OPEN", "RESOLVED", "REGRESSION", "UNVERIFIED")
VERDICTS = ("VERIFIED_RESOLVED", "FIX_REJECTED", "UNVERIFIED", "ERROR")


@dataclass(frozen=True)
class ProjectRow:
    id: int
    name: str
    source_type: str
    repo_url: str | None
    scans: int


@dataclass(frozen=True)
class ScanRow:
    id: int
    label: str | None
    status: str
    source_ref: str | None
    started_at: datetime
    findings: int
    transitions: dict[str, int]
    scanners: dict[str, str]


@dataclass(frozen=True)
class TrackedRow:
    id: int
    status: str
    severity: str
    tool: str
    rule: str
    cwe: str | None
    owasp: str | None
    file_path: str
    line: int | None
    first_seen: int
    last_seen: int
    regressions: int
    verdict: str | None            # latest verification verdict, if any

    @property
    def label(self) -> str:
        return f"#{self.id} {self.severity} {self.rule} {self.file_path}:{self.line or '-'}"


@dataclass(frozen=True)
class EventRow:
    scan_id: int | None
    from_status: str | None
    to_status: str
    unverified: bool
    note: str | None
    created_at: datetime


@dataclass(frozen=True)
class VerificationRow:
    id: int
    tracked_id: int
    mode: str
    verdict: str
    reason: str | None
    gates: list[dict]
    target: list[str]
    before_scan_id: int | None
    after_scan_id: int | None
    strategy: str | None
    model: str | None
    prompt_tokens: int | None
    completion_tokens: int | None
    calls: int
    created_at: datetime


@dataclass(frozen=True)
class Evidence:
    scan_id: int
    tool: str
    rule_id: str
    message: str
    snippet: str
    severity: str
    cwe: str | None
    cwe_reported: str | None
    owasp: str | None
    cve_ids: list[str]
    fix_versions: list[str]
    package: str | None
    package_version: str | None
    file_path: str
    start_line: int | None
    end_line: int | None


@dataclass(frozen=True)
class FindingDetail:
    row: TrackedRow
    evidence: Evidence | None
    events: list[EventRow]
    verifications: list[VerificationRow]
    suppressed_reason: str | None


@dataclass(frozen=True)
class Overview:
    project: ProjectRow
    latest: ScanRow | None
    open_by_severity: dict[str, int]
    states: dict[str, int]
    open_by_owasp: dict[str, int]
    verdicts: dict[str, int]
    scanner_runs: list[dict] = field(default_factory=list)


# ---- helpers --------------------------------------------------------------------


def _short_rule(rule_id: str) -> str:
    return rule_id.split(".")[-1]


def _owasp_by_fingerprint(session, project_id: int) -> dict[str, str | None]:  # noqa: ANN001
    rows = session.execute(select(Finding.fingerprint, Finding.owasp).join(Scan, Finding.scan_id == Scan.id)
                           .where(Scan.project_id == project_id).order_by(Finding.id))
    return {fp: owasp for fp, owasp in rows}


def _latest_verdicts(session, project_id: int) -> dict[int, str]:  # noqa: ANN001
    latest = (select(func.max(Verification.id)).where(Verification.project_id == project_id)
              .group_by(Verification.tracked_finding_id))
    rows = session.scalars(select(Verification).where(Verification.id.in_(latest)))
    return {v.tracked_finding_id: v.verdict.value for v in rows}


def _tracked_row(t: TrackedFinding, owasp: dict[str, str | None], verdicts: dict[int, str]) -> TrackedRow:
    return TrackedRow(t.id, t.status.value, t.severity, t.tool, _short_rule(t.rule_id), t.cwe,
                      owasp.get(t.fingerprint), t.file_path, t.start_line, t.first_seen_scan_id,
                      t.last_seen_scan_id, t.regression_count, verdicts.get(t.id))


def _scan_row(session, scan: Scan) -> ScanRow:  # noqa: ANN001
    counts: Counter[str] = Counter()
    for e in session.scalars(select(LifecycleEvent).where(LifecycleEvent.scan_id == scan.id)):
        counts["UNVERIFIED" if e.unverified else e.to_status.value] += 1
    findings = session.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan.id)) or 0
    runs = session.scalars(select(ScannerRun).where(ScannerRun.scan_id == scan.id).order_by(ScannerRun.id))
    return ScanRow(scan.id, scan.label, scan.status.value, scan.source_ref, scan.started_at, findings,
                   {k: counts.get(k, 0) for k in TRANSITIONS}, {r.tool: r.status.value for r in runs})


def verification_row(v: Verification) -> VerificationRow:
    return VerificationRow(v.id, v.tracked_finding_id, v.mode.value, v.verdict.value, v.reason, list(v.gates or []),
                           list(v.target or []), v.before_scan_id, v.after_scan_id, v.strategy, v.model,
                           v.prompt_tokens, v.completion_tokens, v.calls, v.created_at)


# ---- read models ----------------------------------------------------------------------


def projects() -> list[ProjectRow]:
    with session_scope() as s:
        counts = dict(s.execute(select(Scan.project_id, func.count(Scan.id)).group_by(Scan.project_id)).all())
        return [ProjectRow(p.id, p.name, p.source_type.value, p.repo_url, counts.get(p.id, 0))
                for p in s.scalars(select(Project).order_by(Project.name))]


def project(project_id: int) -> ProjectRow | None:
    return next((p for p in projects() if p.id == project_id), None)


def tracked(project_id: int, states: list[str] | None = None, severities: list[str] | None = None,
            tools: list[str] | None = None) -> list[TrackedRow]:
    with session_scope() as s:
        query = select(TrackedFinding).where(TrackedFinding.project_id == project_id)
        if states:
            query = query.where(TrackedFinding.status.in_([LifecycleState(x) for x in states]))
        if severities:
            query = query.where(TrackedFinding.severity.in_(severities))
        if tools:
            query = query.where(TrackedFinding.tool.in_(tools))
        owasp, verdicts = _owasp_by_fingerprint(s, project_id), _latest_verdicts(s, project_id)
        rows = [_tracked_row(t, owasp, verdicts) for t in s.scalars(query)]
    rank = {sev: i for i, sev in enumerate(SEVERITIES)}
    return sorted(rows, key=lambda r: (STATES.index(r.status), rank.get(r.severity, 9), r.file_path, r.line or 0))


def overview(project_id: int) -> Overview | None:
    proj = project(project_id)
    if proj is None:
        return None
    rows = tracked(project_id)
    open_rows = [r for r in rows if LifecycleState(r.status) in OPEN_STATES]
    with session_scope() as s:
        latest_scan = s.scalars(select(Scan).where(Scan.project_id == project_id)
                                .order_by(Scan.id.desc()).limit(1)).first()
        latest = _scan_row(s, latest_scan) if latest_scan else None
        runs = [{"scanner": r.tool, "status": r.status.value, "version": r.tool_version or "-",
                 "findings": r.finding_count, "seconds": round(r.duration_s or 0.0, 1),
                 "error": r.error or r.notes or ""}
                for r in s.scalars(select(ScannerRun).where(ScannerRun.scan_id == latest_scan.id)
                                   .order_by(ScannerRun.id))] if latest_scan else []
        verdict_counts = Counter(_latest_verdicts(s, project_id).values())
    severity = Counter(r.severity for r in open_rows)
    owasp = Counter(owasp_label(r.owasp) or r.owasp or "Unmapped" for r in open_rows)
    return Overview(
        project=proj, latest=latest,
        open_by_severity={sev: severity.get(sev, 0) for sev in SEVERITIES},
        states={st: sum(r.status == st for r in rows) for st in STATES},
        open_by_owasp=dict(sorted(owasp.items(), key=lambda kv: (-kv[1], kv[0]))),
        verdicts={v: verdict_counts.get(v, 0) for v in VERDICTS},
        scanner_runs=runs,
    )


def scan_history(project_id: int) -> list[ScanRow]:
    with session_scope() as s:
        return [_scan_row(s, scan) for scan in s.scalars(select(Scan).where(Scan.project_id == project_id)
                                                         .order_by(Scan.id))]


def scanner_runs(scan_id: int) -> list[dict]:
    with session_scope() as s:
        return [{"scanner": r.tool, "status": r.status.value, "version": r.tool_version or "-",
                 "ruleset": (r.ruleset_hash or "-")[:12], "findings": r.finding_count,
                 "seconds": round(r.duration_s or 0.0, 1), "error": r.error or r.notes or ""}
                for r in s.scalars(select(ScannerRun).where(ScannerRun.scan_id == scan_id).order_by(ScannerRun.id))]


def verifications(tracked_id: int) -> list[VerificationRow]:
    with session_scope() as s:
        return [verification_row(v) for v in s.scalars(
            select(Verification).where(Verification.tracked_finding_id == tracked_id).order_by(Verification.id.desc()))]


def finding_detail(tracked_id: int) -> FindingDetail | None:
    with session_scope() as s:
        t = s.get(TrackedFinding, tracked_id)
        if t is None:
            return None
        owasp, verdicts = _owasp_by_fingerprint(s, t.project_id), _latest_verdicts(s, t.project_id)
        ev = s.scalars(select(Finding).join(Scan, Finding.scan_id == Scan.id)
                       .where(Scan.project_id == t.project_id, Finding.fingerprint == t.fingerprint)
                       .order_by(Finding.id.desc()).limit(1)).first()
        evidence = Evidence(ev.scan_id, ev.tool, ev.rule_id, ev.message, ev.snippet, ev.severity, ev.cwe,
                            ev.cwe_reported, ev.owasp, list(ev.cve_ids or []), list(ev.fix_versions or []),
                            ev.package, ev.package_version, ev.file_path, ev.start_line, ev.end_line) if ev else None
        events = [EventRow(e.scan_id, e.from_status.value if e.from_status else None, e.to_status.value,
                           e.unverified, e.note, e.created_at) for e in t.events]
        return FindingDetail(_tracked_row(t, owasp, verdicts), evidence, events,
                             [verification_row(v) for v in s.scalars(
                                 select(Verification).where(Verification.tracked_finding_id == t.id)
                                 .order_by(Verification.id.desc()))],
                             t.suppressed_reason)
