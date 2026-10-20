"""Developer-mode verification: judge a fix by comparing two persisted scans of a project.

    developer's assistant edits the code -> developer commits -> rescan (scan-zip / scan-url)
                                          -> verify(tracked id, after scan) -> gates 1, 2, 3a -> verdict

The *before* scan is the latest scan, earlier than the after scan, in which the
finding was present. Comparing with that scan (not simply the previous one)
lets a developer fix a gate-2 problem in a follow-up commit and verify the
original weakness again.

Developer mode never executes repository code: gate 3b is reported as
NOT_APPLICABLE with that reason, so the table always shows all four gates.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Finding, LifecycleState, Scan, ScanStatus, TrackedFinding, Verification, VerificationMode
from app.verification.compare import RescanEvidence, compare, view_from_scan
from app.verification.gates import GateResult, GateStatus
from app.verification.gates.gate1_resolved import gate1_resolved
from app.verification.gates.gate2_no_new import gate2_no_new
from app.verification.gates.gate3a_static import gate3a_static
from app.verification.verdict import Outcome, decide

DEVELOPER_3B = GateResult("3b", "fixture tests", GateStatus.NOT_APPLICABLE,
                          "developer mode never executes repository code")


class VerificationNotFound(LookupError):
    """Unknown tracked finding or scan."""


class NotVerifiable(ValueError):
    """The request names nothing that can be compared. Message is safe to show the user."""


def suppressed_fingerprints(session: Session, project_id: int) -> frozenset[str]:
    return frozenset(session.scalars(select(TrackedFinding.fingerprint).where(
        TrackedFinding.project_id == project_id, TrackedFinding.status == LifecycleState.SUPPRESSED)))


def static_gates(ev: RescanEvidence) -> list[GateResult]:
    """Gates 1, 2 and 3a: the ones both modes share."""
    return [gate1_resolved(ev), gate2_no_new(ev), gate3a_static(ev.symbol_before, ev.symbol_after)]


def _after_scan(session: Session, tracked: TrackedFinding, after_scan_id: int | None) -> Scan:
    if after_scan_id is None:
        scan = session.scalars(select(Scan).where(Scan.project_id == tracked.project_id)
                               .order_by(Scan.id.desc()).limit(1)).first()
    else:
        scan = session.get(Scan, after_scan_id)
    if scan is None or scan.project_id != tracked.project_id:
        raise VerificationNotFound("scan not found for this finding's project")
    if scan.status == ScanStatus.RUNNING:
        raise NotVerifiable(f"scan #{scan.id} is still running")
    return scan


def _before_scan_id(session: Session, tracked: TrackedFinding, after: Scan) -> int:
    before = session.scalar(
        select(func.max(Finding.scan_id)).join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.project_id == tracked.project_id, Finding.fingerprint == tracked.fingerprint,
               Finding.scan_id < after.id))
    if before is None:
        raise NotVerifiable(f"finding #{tracked.id} was not reported by any scan before scan #{after.id}; "
                            "there is no 'before' to compare with")
    return before


def record(session: Session, tracked: TrackedFinding, mode: VerificationMode, outcome: Outcome,
           target: list[str], **fields: object) -> Verification:
    row = Verification(project_id=tracked.project_id, tracked_finding_id=tracked.id, mode=mode,
                       verdict=outcome.verdict, reason=outcome.reason,
                       gates=[g.to_dict() for g in outcome.gates], target=target, **fields)
    session.add(row)
    session.flush()
    return row


def verify(session: Session, tracked_id: int, after_scan_id: int | None = None) -> Verification:
    """Verify the fix of ``tracked_id`` against ``after_scan_id`` (default: the project's latest scan)."""
    tracked = session.get(TrackedFinding, tracked_id)
    if tracked is None:
        raise VerificationNotFound(f"no tracked finding #{tracked_id}")
    after = _after_scan(session, tracked, after_scan_id)
    before_id = _before_scan_id(session, tracked, after)
    ev = compare(tracked.fingerprint, view_from_scan(session, before_id), view_from_scan(session, after.id),
                 suppressed_fingerprints(session, tracked.project_id))
    outcome = decide([*static_gates(ev), DEVELOPER_3B])
    return record(session, tracked, VerificationMode.DEVELOPER, outcome, [m.label for m in ev.group],
                  before_scan_id=before_id, after_scan_id=after.id)


def history(session: Session, tracked_id: int) -> list[Verification]:
    if session.get(TrackedFinding, tracked_id) is None:
        raise VerificationNotFound(f"no tracked finding #{tracked_id}")
    return list(session.scalars(select(Verification).where(Verification.tracked_finding_id == tracked_id)
                                .order_by(Verification.id)))
