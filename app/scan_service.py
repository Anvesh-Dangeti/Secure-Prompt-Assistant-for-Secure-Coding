"""Run a scan of a project and record it: the entry point used by the API and CLI.

    ingest (clone or extract into scratch)  ->  scan_tree  ->  persist  ->  lifecycle

Input is validated *before* anything is written (an unsafe URL never creates
a project or a scan row). Once a scan row exists, every outcome is recorded:
an ingest failure marks it FAILED with a user-safe reason; scanner failures
mark it PARTIAL. Nothing is ever recorded as a clean COMPLETED scan unless
every scanner ran successfully.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.redaction import redact
from app.core.scratch import scratch_dir
from app.db.models import Finding, Project, Scan, ScannerRun, ScanStatus, SourceType
from app.db.session import session_scope
from app.intelligence.tracking import update_tracking
from app.pipeline import TreeScan, scan_tree
from app.scanners import Scanner
from app.repository.git_clone import CloneError, clone
from app.repository.url_validator import UnsafeRepositoryURL, ValidatedRepoURL, validate_repo_url
from app.repository.zip_extract import UnsafeArchiveError, extract_zip

log = get_logger(__name__)
_PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


class InvalidRequest(ValueError):
    """Rejected before any work was done. Message is safe to show the user."""


@dataclass
class ScanSummary:
    scan_id: int
    project_id: int
    project: str
    status: str
    source_ref: str | None
    error: str | None = None
    scanners: dict[str, str] = field(default_factory=dict)
    findings: int = 0
    lifecycle: dict[str, int] = field(default_factory=dict)


def validate_project_name(name: str) -> str:
    if not isinstance(name, str) or not _PROJECT_NAME.match(name):
        raise InvalidRequest("project name must be 1-80 characters of letters, digits, '.', '_' or '-'")
    return name


def check_repo_url(url: str) -> ValidatedRepoURL:
    try:
        return validate_repo_url(url, get_settings().allowed_git_hosts)
    except UnsafeRepositoryURL as exc:
        raise InvalidRequest(str(exc)) from exc


def get_or_create_project(session: Session, name: str, source_type: SourceType, repo_url: str | None) -> Project:
    project = session.scalars(select(Project).where(Project.name == name)).first()
    if project is None:
        project = Project(name=name, source_type=source_type, repo_url=repo_url)
        session.add(project)
        session.flush()
    elif project.source_type != source_type:
        raise InvalidRequest(f"project {name!r} is a {project.source_type.value} project")
    elif repo_url and project.repo_url and project.repo_url != repo_url:
        raise InvalidRequest(f"project {name!r} tracks a different repository")
    return project


def _persist_results(session: Session, scan: Scan, tree: TreeScan) -> None:
    for result in tree.results:
        notes = list(result.notes)
        if result.unverified_scopes:
            notes.append(f"{len(result.unverified_scopes)} scope(s) not verifiable")
        session.add(ScannerRun(
            scan_id=scan.id, tool=result.tool, tool_version=result.version, ruleset_hash=result.ruleset_hash,
            status=result.status, duration_s=result.duration_s, finding_count=len(result.findings),
            error=result.error, notes="; ".join(notes) or None,
        ))
        for f in result.findings:
            session.add(Finding(
                scan_id=scan.id, tool=f.tool, rule_id=f.rule_id, fingerprint=f.fingerprint,
                fingerprint_source=f.fingerprint_source, severity=f.severity, cwe=f.cwe,
                cwe_reported=f.cwe_reported, owasp=f.owasp, cve_ids=f.cve_ids, in_scope=f.in_scope,
                file_path=f.file_path, start_line=f.start_line, end_line=f.end_line,
                message=redact(f.message), snippet=redact(f.snippet), package=f.package,
                package_version=f.package_version, fix_versions=f.fix_versions,
            ))


def _scan_status(tree: TreeScan) -> ScanStatus:
    if tree.all_ok:
        return ScanStatus.COMPLETED
    if any(r.ok for r in tree.results):
        return ScanStatus.PARTIAL
    return ScanStatus.FAILED


Ingest = Callable[[Path], tuple[Path, str]]


def _run(project_name: str, source_type: SourceType, repo_url: str | None, ingest: Ingest,
         label: str | None, scanners: list[Scanner] | None = None) -> ScanSummary:
    with session_scope() as session:
        project = get_or_create_project(session, project_name, source_type, repo_url)
        scan = Scan(project_id=project.id, source_type=source_type, label=label, status=ScanStatus.RUNNING)
        session.add(scan)
        session.flush()
        scan_id, project_id = scan.id, project.id

    tree: TreeScan | None = None
    source_ref: str | None = None
    error: str | None = None
    try:
        with scratch_dir("scan-") as work:
            out = work / "out"
            out.mkdir()
            root, source_ref = ingest(work)
            tree = scan_tree(root, out, scanners)
    except (UnsafeArchiveError, CloneError, UnsafeRepositoryURL) as exc:
        error = str(exc)
    except Exception as exc:  # noqa: BLE001 -- recorded as FAILED, never as success
        log.exception("scan crashed", extra={"scan_id": scan_id})
        error = f"internal error ({type(exc).__name__})"

    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        scan.source_ref = source_ref
        scan.finished_at = datetime.now(timezone.utc)
        lifecycle: dict[str, int] = {}
        if tree is None:
            scan.status = ScanStatus.FAILED
            scan.error = redact(error or "scan failed")
        else:
            scan.status = _scan_status(tree)
            _persist_results(session, scan, tree)
            session.flush()
            lifecycle = update_tracking(session, scan, tree)
        return ScanSummary(
            scan_id=scan_id, project_id=project_id, project=project_name, status=scan.status.value,
            source_ref=source_ref, error=scan.error,
            scanners={r.tool: r.status.value for r in tree.results} if tree else {},
            findings=len(tree.findings) if tree else 0, lifecycle=lifecycle,
        )


def scan_git(project_name: str, url: str, label: str | None = None) -> ScanSummary:
    validate_project_name(project_name)
    validated = check_repo_url(url)   # before any row is written

    def ingest(work: Path) -> tuple[Path, str]:
        dest = work / "src"
        return dest, clone(validated, dest)

    return _run(project_name, SourceType.GIT, validated.url, ingest, label)


def scan_zip(project_name: str, archive: Path, label: str | None = None,
             scanners: list[Scanner] | None = None) -> ScanSummary:
    """Scan an uploaded archive. ``archive`` must already be inside scratch space.

    ``scanners`` overrides the scanner set (tests and the outage demo only).
    """
    validate_project_name(project_name)

    def ingest(work: Path) -> tuple[Path, str]:
        extracted = extract_zip(archive, work / "src")
        return extracted.root, extracted.sha256

    return _run(project_name, SourceType.ZIP, None, ingest, label, scanners)
