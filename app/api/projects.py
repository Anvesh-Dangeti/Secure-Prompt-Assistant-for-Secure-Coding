"""Projects and scans.

Every route requires the API key (router-level dependency, so a new route
cannot forget it). Scans run synchronously: the tool is on-demand and
single-user, and a synchronous call means the caller sees the real outcome.

Uploads are streamed to scratch with a hard byte cap -- the request body is
never held in memory and never trusted for its declared size.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_db, require_api_key
from app.api.schemas import FindingOut, GitScanRequest, ProjectCreate, ProjectOut, ScanOut, ScanSummaryOut
from app.core.config import get_settings
from app.core.scratch import scratch_dir
from app.db.models import Finding, Project, Scan, SourceType
from app.scan_service import InvalidRequest, check_repo_url, scan_git, scan_zip, validate_project_name

router = APIRouter(prefix="/api/v1", tags=["projects"], dependencies=[Depends(require_api_key)])


def _project_or_404(db: Session, project_id: int) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return project


@router.post("/projects", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(body: ProjectCreate, db: Session = Depends(get_db)) -> Project:
    try:
        validate_project_name(body.name)
        repo_url = check_repo_url(body.repo_url).url if body.repo_url else None
    except InvalidRequest as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if db.scalars(select(Project).where(Project.name == body.name)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "project already exists")
    project = Project(name=body.name, source_type=SourceType.GIT if repo_url else SourceType.ZIP,
                      repo_url=repo_url)
    db.add(project)
    db.flush()
    return project


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db)) -> list[Project]:
    return list(db.scalars(select(Project).order_by(Project.id)))


@router.post("/projects/{project_id}/scans/git", response_model=ScanSummaryOut)
def run_git_scan(project_id: int, body: GitScanRequest | None = None, db: Session = Depends(get_db)) -> dict:
    project = _project_or_404(db, project_id)
    if project.source_type != SourceType.GIT or not project.repo_url:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "project has no repository URL")
    name, url = project.name, project.repo_url
    db.close()  # the scan opens its own sessions
    try:
        return asdict(scan_git(name, url, label=body.label if body else None))
    except InvalidRequest as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.post("/projects/{project_id}/scans/zip", response_model=ScanSummaryOut)
def run_zip_scan(project_id: int, archive: UploadFile = File(...), label: str | None = None,
                 db: Session = Depends(get_db)) -> dict:
    project = _project_or_404(db, project_id)
    if project.source_type != SourceType.ZIP:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "project tracks a git repository; use the git scan")
    if label is not None and len(label) > 120:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "label too long")
    name = project.name
    db.close()
    limit = get_settings().max_upload_bytes
    with scratch_dir("upload-") as upload_dir:
        target = upload_dir / "upload.zip"
        received = 0
        with target.open("wb") as out:
            while chunk := archive.file.read(1 << 16):
                received += len(chunk)
                if received > limit:
                    raise HTTPException(413, "archive too large")
                out.write(chunk)
        summary = scan_zip(name, target, label=label)
    if summary.status == "FAILED" and summary.error and summary.scanners == {}:
        # Archive refused during extraction: report it as a client error.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, summary.error)
    return asdict(summary)


@router.get("/projects/{project_id}/scans", response_model=list[ScanOut])
def list_scans(project_id: int, db: Session = Depends(get_db)) -> list[Scan]:
    _project_or_404(db, project_id)
    query = select(Scan).where(Scan.project_id == project_id).options(selectinload(Scan.scanner_runs))
    return list(db.scalars(query.order_by(Scan.id)))


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return scan


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_scan_findings(scan_id: int, in_scope_only: bool = False, db: Session = Depends(get_db)) -> list[Finding]:
    if db.get(Scan, scan_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    query = select(Finding).where(Finding.scan_id == scan_id)
    if in_scope_only:
        query = query.where(Finding.in_scope.is_(True))
    return list(db.scalars(query.order_by(Finding.file_path, Finding.start_line)))
