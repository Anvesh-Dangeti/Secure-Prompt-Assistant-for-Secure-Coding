"""Apply the lifecycle state machine to a project after each scan, and record history.

One ``TrackedFinding`` per (project, fingerprint) carries the current state;
one ``LifecycleEvent`` per finding per scan records what happened, so the
history of every weakness is auditable rather than reconstructed.

Suppression (a human marking a false positive) is the only state change that
does not come from a scan. It requires a reason, keeps the record, and is
excluded from NEW/REGRESSION counting -- a suppressed finding is never lost.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.redaction import redact
from app.db.models import LifecycleEvent, LifecycleState, Scan, TrackedFinding
from app.intelligence.lifecycle import classify_scan
from app.normalization.finding import NormalizedFinding
from app.pipeline import TreeScan

UNVERIFIED = "UNVERIFIED"
MAX_REASON = 500


class TrackingError(ValueError):
    """Invalid lifecycle request (unknown finding, missing reason...)."""


def _new_tracked(project_id: int, scan_id: int, f: NormalizedFinding) -> TrackedFinding:
    return TrackedFinding(
        project_id=project_id, fingerprint=f.fingerprint, tool=f.tool, rule_id=f.rule_id, cwe=f.cwe,
        severity=f.severity, file_path=f.file_path, start_line=f.start_line, message=redact(f.message)[:2000],
        scope_key=f.scope_key, status=LifecycleState.NEW, first_seen_scan_id=scan_id, last_seen_scan_id=scan_id,
    )


def update_tracking(session: Session, scan: Scan, tree: TreeScan) -> dict[str, int]:
    """Advance every tracked finding of ``scan.project`` and return per-state counts."""
    tracked = {t.fingerprint: t for t in session.scalars(
        select(TrackedFinding).where(TrackedFinding.project_id == scan.project_id))}
    current = {f.fingerprint: f for f in tree.findings}
    tool_ok = {r.tool: r.ok for r in tree.results}
    blind_spots = {r.tool: r.unverified_scopes for r in tree.results}

    verifiable = {
        fp: tool_ok.get(t.tool, False) and t.scope_key not in blind_spots.get(t.tool, set())
        for fp, t in tracked.items()
    }
    transitions = classify_scan({fp: t.status for fp, t in tracked.items()}, set(current), verifiable)

    counts: Counter[str] = Counter()
    for tr in transitions:
        t = tracked.get(tr.fingerprint)
        if t is None:
            t = _new_tracked(scan.project_id, scan.id, current[tr.fingerprint])
            session.add(t)
            session.flush()
        if tr.present:
            f = current[tr.fingerprint]
            t.last_seen_scan_id = scan.id
            # Location and wording may move; identity (the fingerprint) does not.
            t.file_path, t.start_line, t.severity = f.file_path, f.start_line, f.severity
        if tr.to_status == LifecycleState.RESOLVED and tr.changed:
            t.resolved_in_scan_id = scan.id
        if tr.to_status == LifecycleState.REGRESSION:
            t.regression_count += 1
            t.resolved_in_scan_id = None
        t.status = tr.to_status

        quiet = (not tr.changed and tr.to_status in {LifecycleState.RESOLVED, LifecycleState.SUPPRESSED}
                 and not tr.unverified)
        if not quiet:
            session.add(LifecycleEvent(
                tracked_finding_id=t.id, scan_id=scan.id, from_status=tr.from_status, to_status=tr.to_status,
                unverified=tr.unverified,
                note="absent, but its scanner could not verify this scope" if tr.unverified else None,
            ))
        # Counts describe what THIS scan did: NEW/RESOLVED/REGRESSION are
        # transitions; STILL_OPEN and SUPPRESSED are what carries forward.
        if tr.unverified:
            counts[UNVERIFIED] += 1
        elif tr.to_status != LifecycleState.RESOLVED or tr.changed:
            counts[tr.to_status.value] += 1
    return {k: counts.get(k, 0) for k in ("NEW", "STILL_OPEN", "RESOLVED", "REGRESSION", "SUPPRESSED", UNVERIFIED)}


def suppress(session: Session, tracked_id: int, reason: str) -> TrackedFinding:
    reason = (reason or "").strip()
    if not reason:
        raise TrackingError("a reason is required to suppress a finding")
    t = session.get(TrackedFinding, tracked_id)
    if t is None:
        raise TrackingError("tracked finding not found")
    if t.status == LifecycleState.SUPPRESSED:
        return t
    session.add(LifecycleEvent(tracked_finding_id=t.id, scan_id=None, from_status=t.status,
                               to_status=LifecycleState.SUPPRESSED, note=redact(reason)[:MAX_REASON]))
    t.status = LifecycleState.SUPPRESSED
    t.suppressed_reason = redact(reason)[:MAX_REASON]
    t.suppressed_at = datetime.now(timezone.utc)
    return t


def unsuppress(session: Session, tracked_id: int) -> TrackedFinding:
    """Re-open a suppressed finding; the next scan decides its real state."""
    t = session.get(TrackedFinding, tracked_id)
    if t is None:
        raise TrackingError("tracked finding not found")
    if t.status != LifecycleState.SUPPRESSED:
        raise TrackingError("finding is not suppressed")
    session.add(LifecycleEvent(tracked_finding_id=t.id, scan_id=None, from_status=LifecycleState.SUPPRESSED,
                               to_status=LifecycleState.STILL_OPEN, note="suppression withdrawn"))
    t.status = LifecycleState.STILL_OPEN
    t.suppressed_reason = None
    t.suppressed_at = None
    return t
