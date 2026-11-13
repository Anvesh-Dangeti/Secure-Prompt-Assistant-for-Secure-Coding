"""From a tracked finding (what the developer sees in ``findings``) to a context.

Scans keep evidence, not source code: every clone or upload is deleted after
scanning. So in developer mode the code comes from the developer's own
checkout (``source_root``) -- the same code they will hand to their assistant
and commit. The finding's stored snippet is compared with that checkout; a
mismatch means the checkout has moved on since the scan and is reported.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.context import ContextError, FindingContext, extract_context
from app.ai.explainer import explain
from app.ai.linter import LintExpectation, expectation_for
from app.ai.prompt_builder import build_prompt
from app.ai.strategies import DEFAULT_STRATEGY
from app.db.models import Finding, Scan, TrackedFinding
from app.normalization.finding import NormalizedFinding


class FindingNotFound(LookupError):
    pass


def _evidence_row(session: Session, tracked_id: int) -> Finding:
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
    return row


def finding_for_tracked(session: Session, tracked_id: int) -> NormalizedFinding:
    """The latest scanner evidence for a tracked finding, detached from the session."""
    return _normalized(_evidence_row(session, tracked_id))


def dependency_group(session: Session, tracked_id: int) -> list[NormalizedFinding]:
    """The other advisories on the same dependency in the same scan (empty for code findings).

    The prompt for one advisory must name a version that fixes all of them,
    because verification targets the whole weakness group.
    """
    row = _evidence_row(session, tracked_id)
    if not row.package:
        return []
    siblings = session.scalars(
        select(Finding).where(Finding.scan_id == row.scan_id, Finding.package == row.package,
                              Finding.file_path == row.file_path, Finding.id != row.id)
    ).all()
    return [_normalized(f) for f in siblings]


def _normalized(row: Finding) -> NormalizedFinding:
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
    return extract_context(finding_for_tracked(session, tracked_id), source_root,
                           group=dependency_group(session, tracked_id))


STALE_SOURCE = "the code differs from the scanned version; rescan for exact context"


@dataclass(frozen=True)
class PromptResult:
    """A developer-mode prompt, ready to show: what to paste and how it linted."""

    strategy: str
    rendered: str
    lint: dict
    tokens: int
    explanation_source: str
    warning: str | None


def prompt_for_context(ctx: FindingContext, strategy: str = DEFAULT_STRATEGY) -> PromptResult:
    """Explain, build and lint one prompt (raises ``PromptRejected`` or ``ValueError`` for a bad strategy)."""
    plan = build_prompt(ctx, strategy, explanation=explain(ctx))
    return PromptResult(plan.strategy, plan.render(), plan.lint.to_dict(), plan.estimated_tokens,
                        plan.explanation.source, STALE_SOURCE if ctx.snippet_verified is False else None)


def bound_expectation(ctx: FindingContext) -> LintExpectation:
    """What a developer-edited prompt for this finding is linted against.

    The canonical S7 first message is the reference for the "no silent
    shortening" rule (A7). One definition, so the CLI and the dashboard lint
    an edited prompt identically.
    """
    return expectation_for(ctx, canonical=build_prompt(ctx, DEFAULT_STRATEGY).messages[0])
