"""The actions the dashboard may take -- thin, validated wrappers over the same services as the CLI.

Nothing here adds a capability the CLI lacks: scan a local checkout, rescan,
verify against a scan, suppress with a reason, build a prompt, lint a prompt.
Lab mode is deliberately absent -- it is the only path that executes code, and
it stays a local CLI instrument.

Every error is turned into an ``ActionError`` whose message is safe to show.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.ai.context import ContextError
from app.ai.explainer import explain
from app.ai.linter import apply_fixes, lint, unbound_expectation
from app.ai.prompt_builder import PromptRejected, build_prompt
from app.ai.service import FindingNotFound, bound_expectation, context_for_tracked
from app.ai.strategies import STRATEGIES
from app.cli import zip_directory
from app.cli_ai import MAX_PROMPT_INPUT
from app.core.config import get_settings
from app.core.paths import is_within
from app.core.scratch import scratch_dir
from app.db.models import Project, SourceType, TrackedFinding
from app.db.session import session_scope
from app.intelligence.tracking import TrackingError, suppress, unsuppress
from app.scan_service import InvalidRequest, ScanSummary, scan_git, scan_zip
from app.verification.service import NotVerifiable, VerificationNotFound, verify
from dashboard.data import VerificationRow, verification_row

MIN_REASON = 3


class ActionError(ValueError):
    """The action was refused or failed. Message is safe to show the user."""


def checkout_path(raw: str | None) -> Path:
    """A developer's local checkout: an existing absolute directory, outside scratch, inside the allowed root.

    Relative paths are refused because they would resolve against the server's
    working directory, not anything the user can see.
    """
    text = (raw or "").strip().strip('"')
    if not text:
        raise ActionError("give the absolute path of your checkout")
    if "\x00" in text:
        raise ActionError("invalid path")
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise ActionError("give an absolute path (relative paths would depend on where the dashboard runs)")
    path = path.resolve()
    if not path.is_dir():
        raise ActionError(f"not a directory: {path}")
    settings = get_settings()
    if is_within(path, settings.scratch_root):
        raise ActionError("scratch space is not a checkout")
    if settings.dashboard_source_root and not is_within(path, settings.dashboard_source_root):
        raise ActionError("that path is outside the directory this dashboard may read (SPA_DASHBOARD_SOURCE_ROOT)")
    return path


# ---- scanning and verification ----------------------------------------------------


def scan_checkout(project_name: str, raw_path: str | None, label: str | None = None) -> ScanSummary:
    """Scan a local checkout into a (new or existing) ZIP project, through the validated upload path."""
    source = checkout_path(raw_path)
    with scratch_dir("dash-") as work:
        archive = work / f"{source.name or 'checkout'}.zip"
        zip_directory(source, archive)
        try:
            summary = scan_zip(project_name, archive, label=(label or None))
        except InvalidRequest as exc:
            raise ActionError(str(exc)) from exc
    if summary.status == "FAILED" and not summary.scanners:
        raise ActionError(f"scan failed: {summary.error}")
    return summary


def rescan(project_id: int, raw_path: str | None = None, label: str | None = None) -> ScanSummary:
    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise ActionError("project not found")
        name, kind, url = project.name, project.source_type, project.repo_url
    if kind == SourceType.ZIP:
        return scan_checkout(name, raw_path, label)
    if not url:
        raise ActionError("this project has no repository URL")
    try:
        return scan_git(name, url, label=label)
    except InvalidRequest as exc:
        raise ActionError(str(exc)) from exc


def verify_against(tracked_id: int, scan_id: int | None = None) -> VerificationRow:
    try:
        with session_scope() as s:
            return verification_row(verify(s, tracked_id, scan_id))
    except (VerificationNotFound, NotVerifiable) as exc:
        raise ActionError(str(exc)) from exc


def rescan_and_verify(tracked_id: int, raw_path: str | None = None) -> tuple[ScanSummary, VerificationRow]:
    """The developer-mode loop's last step: scan the fixed code, then run gates 1, 2, 3a."""
    with session_scope() as s:
        tracked = s.get(TrackedFinding, tracked_id)
        if tracked is None:
            raise ActionError(f"no tracked finding #{tracked_id}")
        project_id = tracked.project_id
    summary = rescan(project_id, raw_path, label=f"verify #{tracked_id}")
    return summary, verify_against(tracked_id, summary.scan_id)


def suppress_finding(tracked_id: int, reason: str | None) -> None:
    reason = (reason or "").strip()
    if len(reason) < MIN_REASON:
        raise ActionError(f"a reason of at least {MIN_REASON} characters is required")
    try:
        with session_scope() as s:
            suppress(s, tracked_id, reason)
    except TrackingError as exc:
        raise ActionError(str(exc)) from exc


def unsuppress_finding(tracked_id: int) -> None:
    try:
        with session_scope() as s:
            unsuppress(s, tracked_id)
    except TrackingError as exc:
        raise ActionError(str(exc)) from exc


# ---- prompts and linting --------------------------------------------------------------


@dataclass(frozen=True)
class PromptView:
    strategy: str
    rendered: str
    report: dict
    tokens: int
    explanation_source: str
    warning: str | None


@dataclass(frozen=True)
class LintView:
    report: dict
    fixed: str | None = None
    fixed_report: dict | None = None


def _context(tracked_id: int, raw_path: str | None):  # noqa: ANN202
    path = checkout_path(raw_path)
    try:
        with session_scope() as s:
            return context_for_tracked(s, tracked_id, path)
    except (FindingNotFound, ContextError) as exc:
        raise ActionError(str(exc)) from exc


def prompt_for(tracked_id: int, raw_path: str | None, strategy: str) -> PromptView:
    if strategy not in STRATEGIES:
        raise ActionError(f"unknown strategy {strategy!r}")
    ctx = _context(tracked_id, raw_path)
    try:
        plan = build_prompt(ctx, strategy, explanation=explain(ctx))
    except PromptRejected as exc:
        raise ActionError(str(exc)) from exc
    warning = ("the code in this checkout differs from the scanned version; rescan for exact context"
               if ctx.snippet_verified is False else None)
    return PromptView(plan.strategy, plan.render(), plan.lint.to_dict(), plan.estimated_tokens,
                      plan.explanation.source, warning)


def lint_text(text: str, tracked_id: int | None = None, raw_path: str | None = None, fix: bool = False) -> LintView:
    """Lint a (developer-edited) prompt, optionally bound to a finding -- the same rules as ``lint-prompt``."""
    if len(text) > MAX_PROMPT_INPUT:
        raise ActionError("prompt too large to lint")
    if not text.strip():
        raise ActionError("paste a prompt to lint")
    expectation = bound_expectation(_context(tracked_id, raw_path)) if tracked_id is not None else None
    report = lint(text, expectation)
    if not fix:
        return LintView(report.to_dict())
    fixed = apply_fixes(text, report, expectation or unbound_expectation())
    return LintView(report.to_dict(), fixed, lint(fixed, expectation).to_dict())
