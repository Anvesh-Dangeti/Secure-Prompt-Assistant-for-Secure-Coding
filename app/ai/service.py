"""From a tracked finding (what the developer sees in ``findings``) to a context.

Scans keep evidence, not source code: every clone or upload is deleted after
scanning. So in developer mode the code comes from the developer's own
checkout (``source_root``) -- the same code they will hand to their assistant
and commit. The finding's stored snippet is compared with that checkout; a
mismatch means the checkout has moved on since the scan and is reported.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.context import ContextError, FindingContext, extract_context
from app.db.models import Finding, Scan, TrackedFinding
from app.normalization.finding import NormalizedFinding


class FindingNotFound(LookupError):
    pass


def finding_for_tracked(session: Session, tracked_id: int) -> NormalizedFinding:
    """The latest scanner evidence for a tracked finding, detached from the session."""
    tracked = session.get(TrackedFinding, tracked_id)
    if tracked is None:
        raise FindingNotFound(f"no tracked finding #{tracked_id}")
    row = session.scalars(
        select(Finding).join(Scan)
        .where(Scan.project_id == tracked.project_id, Finding.fingerprint == tracked.fingerprint)
        .order_by(Finding.id.desc()).limit(1)
    ).first()
    if row is None:
        raise FindingNotFound(f"tracked finding #{tracked_id} has no stored evidence")
    return NormalizedFinding(
        tool=row.tool, rule_id=row.rule_id, message=row.message, file_path=row.file_path,
        start_line=row.start_line, end_line=row.end_line, severity=row.severity, snippet=row.snippet,
        cwe_reported=row.cwe_reported, package=row.package, package_version=row.package_version,
        cve_ids=list(row.cve_ids or []), fix_versions=list(row.fix_versions or []),
        cwe=row.cwe, owasp=row.owasp, in_scope=row.in_scope, fingerprint=row.fingerprint,
        fingerprint_source=row.fingerprint_source,
    )


def context_for_tracked(session: Session, tracked_id: int, source_root: Path) -> FindingContext:
    if not source_root.is_dir():
        raise ContextError(f"source directory not found: {source_root}")
    return extract_context(finding_for_tracked(session, tracked_id), source_root)
