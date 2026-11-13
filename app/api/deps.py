"""Shared API dependencies: authentication, authorization and database sessions.

Two kinds of caller:

* **Administrator** -- the single ``SPA_API_KEY``, sent in ``X-API-Key``. It
  fails closed: if no key is configured, the key path refuses to serve at all
  rather than serving unauthenticated.
* **Developer** -- a per-project access token, sent as ``Authorization: Bearer
  spa_pat_...`` (see ``app.access_tokens``). It reaches one project only.

Every router declares ``current_principal`` at router level, so a new route
cannot forget authentication; routes that touch a project then call
``authorize_project``. A token asking for another project's data gets the same
404 as for data that does not exist, so it cannot learn which projects exist.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.access_tokens import resolve
from app.core.config import get_settings
from app.db.session import new_session, session_scope

# Declared as security schemes so the OpenAPI docs offer an "Authorize" box;
# auto_error=False so the checks below decide the status code (401 vs 503).
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_bearer = HTTPBearer(auto_error=False)


def require_api_key(x_api_key: str | None = Security(_api_key_header)) -> None:
    """The administrator's key. Used alone by administrator-only routes."""
    configured = get_settings().api_key
    if configured is None or not configured.get_secret_value():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API key not configured; protected endpoints are disabled",
        )
    # Constant-time comparison: response timing must not reveal the key prefix.
    if x_api_key is None or not secrets.compare_digest(
        x_api_key.encode("utf-8"), configured.get_secret_value().encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


@dataclass(frozen=True)
class Principal:
    """Who is calling. Holds no secret."""

    kind: str                          # "admin" | "token"
    project_id: int | None = None      # tokens only
    project: str | None = None
    token_id: int | None = None
    token_name: str | None = None
    expires_at: datetime | None = None

    @property
    def is_admin(self) -> bool:
        return self.kind == "admin"


ADMIN = Principal("admin")


def current_principal(x_api_key: str | None = Security(_api_key_header),
                      bearer: HTTPAuthorizationCredentials | None = Security(_bearer)) -> Principal:
    if bearer is not None:
        # A bearer token is checked on its own and wins over any key also sent,
        # so a request is never granted more than the narrowest credential it carries.
        with session_scope() as session:
            identity = resolve(session, bearer.credentials)
        if identity is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid, expired or revoked access token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return Principal("token", identity.project_id, identity.project, identity.id, identity.name,
                         identity.expires_at)
    require_api_key(x_api_key)
    return ADMIN


def authorize_project(principal: Principal, project_id: int, not_found: str = "project not found") -> None:
    """Refuse (as 404) a token that asks for a project other than its own."""
    if not principal.is_admin and principal.project_id != project_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, not_found)


def require_admin(principal: Principal = Depends(current_principal)) -> Principal:
    if not principal.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "this action needs the administrator key")
    return principal


def get_db() -> Iterator[Session]:
    session = new_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
