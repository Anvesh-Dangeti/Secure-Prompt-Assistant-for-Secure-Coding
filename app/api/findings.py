"""Tracked findings: lifecycle state, history, and suppression of false positives."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, authorize_project, current_principal, get_db
from app.api.schemas import SuppressRequest, TrackedDetailOut, TrackedOut
from app.db.models import LifecycleState, Project, TrackedFinding
from app.intelligence.tracking import TrackingError, suppress, unsuppress

router = APIRouter(prefix="/api/v1", tags=["findings"], dependencies=[Depends(current_principal)])

NOT_FOUND = "tracked finding not found"


def tracked_or_404(db: Session, tracked_id: int, principal: Principal) -> TrackedFinding:
    """The tracked finding, if it exists and belongs to a project the caller may see."""
    tracked = db.get(TrackedFinding, tracked_id)
    if tracked is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, NOT_FOUND)
    authorize_project(principal, tracked.project_id, NOT_FOUND)
    return tracked


@router.get("/projects/{project_id}/findings", response_model=list[TrackedOut])
def list_tracked(project_id: int, state: LifecycleState | None = None, db: Session = Depends(get_db),
                 principal: Principal = Depends(current_principal)) -> list[TrackedFinding]:
    authorize_project(principal, project_id)
    if db.get(Project, project_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    query = select(TrackedFinding).where(TrackedFinding.project_id == project_id)
    if state is not None:
        query = query.where(TrackedFinding.status == state)
    return list(db.scalars(query.order_by(TrackedFinding.file_path, TrackedFinding.start_line)))


@router.get("/tracked/{tracked_id}", response_model=TrackedDetailOut)
def get_tracked(tracked_id: int, db: Session = Depends(get_db),
                principal: Principal = Depends(current_principal)) -> TrackedFinding:
    return tracked_or_404(db, tracked_id, principal)


@router.post("/tracked/{tracked_id}/suppress", response_model=TrackedOut)
def suppress_tracked(tracked_id: int, body: SuppressRequest, db: Session = Depends(get_db),
                     principal: Principal = Depends(current_principal)) -> TrackedFinding:
    tracked_or_404(db, tracked_id, principal)
    try:
        return suppress(db, tracked_id, body.reason)
    except TrackingError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND if "not found" in str(exc) else 400, str(exc)) from exc


@router.post("/tracked/{tracked_id}/unsuppress", response_model=TrackedOut)
def unsuppress_tracked(tracked_id: int, db: Session = Depends(get_db),
                       principal: Principal = Depends(current_principal)) -> TrackedFinding:
    tracked_or_404(db, tracked_id, principal)
    try:
        return unsuppress(db, tracked_id)
    except TrackingError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND if "not found" in str(exc) else 400, str(exc)) from exc
