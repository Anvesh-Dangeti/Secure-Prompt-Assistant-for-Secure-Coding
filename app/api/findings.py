"""Tracked findings: lifecycle state, history, and suppression of false positives."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_api_key
from app.api.schemas import SuppressRequest, TrackedDetailOut, TrackedOut
from app.db.models import LifecycleState, Project, TrackedFinding
from app.intelligence.tracking import TrackingError, suppress, unsuppress

router = APIRouter(prefix="/api/v1", tags=["findings"], dependencies=[Depends(require_api_key)])


@router.get("/projects/{project_id}/findings", response_model=list[TrackedOut])
def list_tracked(project_id: int, state: LifecycleState | None = None, db: Session = Depends(get_db)
                 ) -> list[TrackedFinding]:
    if db.get(Project, project_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    query = select(TrackedFinding).where(TrackedFinding.project_id == project_id)
    if state is not None:
        query = query.where(TrackedFinding.status == state)
    return list(db.scalars(query.order_by(TrackedFinding.file_path, TrackedFinding.start_line)))


@router.get("/tracked/{tracked_id}", response_model=TrackedDetailOut)
def get_tracked(tracked_id: int, db: Session = Depends(get_db)) -> TrackedFinding:
    tracked = db.get(TrackedFinding, tracked_id)
    if tracked is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tracked finding not found")
    return tracked


@router.post("/tracked/{tracked_id}/suppress", response_model=TrackedOut)
def suppress_tracked(tracked_id: int, body: SuppressRequest, db: Session = Depends(get_db)) -> TrackedFinding:
    try:
        return suppress(db, tracked_id, body.reason)
    except TrackingError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND if "not found" in str(exc) else 400, str(exc)) from exc


@router.post("/tracked/{tracked_id}/unsuppress", response_model=TrackedOut)
def unsuppress_tracked(tracked_id: int, db: Session = Depends(get_db)) -> TrackedFinding:
    try:
        return unsuppress(db, tracked_id)
    except TrackingError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND if "not found" in str(exc) else 400, str(exc)) from exc
