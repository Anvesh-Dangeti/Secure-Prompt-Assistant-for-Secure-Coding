"""Verification results: judge an existing scan, read the remediation history.

Only developer-mode verification is exposed. It compares two scans that
already exist and executes nothing. Lab mode -- the one path that runs code
(gate 3b) -- is deliberately not reachable over HTTP; it is a local CLI
instrument for experiments.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_api_key
from app.api.schemas import VerificationOut
from app.db.models import Verification
from app.verification.service import NotVerifiable, VerificationNotFound, history, verify

router = APIRouter(prefix="/api/v1", tags=["verification"], dependencies=[Depends(require_api_key)])


@router.post("/tracked/{tracked_id}/verify", response_model=VerificationOut)
def verify_tracked(tracked_id: int, scan_id: int | None = None, db: Session = Depends(get_db)) -> Verification:
    """Verify a fix against ``scan_id`` (default: the project's latest scan). Scan first, then verify."""
    try:
        return verify(db, tracked_id, scan_id)
    except VerificationNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except NotVerifiable as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


@router.get("/tracked/{tracked_id}/verifications", response_model=list[VerificationOut])
def list_verifications(tracked_id: int, db: Session = Depends(get_db)) -> list[Verification]:
    try:
        return history(db, tracked_id)
    except VerificationNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
