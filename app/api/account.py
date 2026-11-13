"""Who am I? Lets the ``spa`` connector check a token before it saves it."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import Principal, current_principal
from app.api.schemas import WhoAmIOut

router = APIRouter(prefix="/api/v1", tags=["account"])


@router.get("/whoami", response_model=WhoAmIOut)
def whoami(principal: Principal = Depends(current_principal)) -> WhoAmIOut:
    # Identity only: never the token, its hash, or anything about other projects.
    return WhoAmIOut(kind=principal.kind, token_id=principal.token_id, token_name=principal.token_name,
                     project_id=principal.project_id, project=principal.project, expires_at=principal.expires_at)
