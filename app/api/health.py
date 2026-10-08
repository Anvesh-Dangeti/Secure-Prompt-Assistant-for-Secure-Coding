"""Health and system-information endpoints.

``/health`` is the only unauthenticated route. It reports liveness and whether
dependencies are usable -- never paths, versions or configuration, which belong
behind authentication.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.api.deps import require_api_key
from app.core.config import get_settings
from app.db.models import Project
from app.db.session import new_session

router = APIRouter()


def _database_ok() -> bool:
    try:
        with new_session() as session:
            session.execute(select(Project.id).limit(1))
        return True
    except SQLAlchemyError:
        return False


@router.get("/health", tags=["system"])
def health() -> dict[str, object]:
    db_ok = _database_ok()
    return {"status": "ok" if db_ok else "degraded", "database": "ok" if db_ok else "error"}


@router.get("/api/v1/system/info", tags=["system"], dependencies=[Depends(require_api_key)])
def system_info() -> dict[str, object]:
    settings = get_settings()
    return {
        "version": __version__,
        "limits": {
            "scanner_timeout_seconds": settings.scanner_timeout_seconds,
            "clone_timeout_seconds": settings.clone_timeout_seconds,
            "max_upload_bytes": settings.max_upload_bytes,
            "max_extracted_bytes": settings.max_extracted_bytes,
            "max_archive_files": settings.max_archive_files,
            "max_repo_bytes": settings.max_repo_bytes,
        },
        "allowed_git_hosts": settings.allowed_git_hosts,
    }
