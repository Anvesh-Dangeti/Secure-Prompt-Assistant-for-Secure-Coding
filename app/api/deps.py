"""Shared API dependencies: authentication and database sessions.

Authentication is a single API key sent in ``X-API-Key``. That is proportionate
for a single-user local tool (multi-user RBAC is out of scope), but it is applied
to *every* route except the health check, and it fails closed: if no key is
configured the protected API refuses to serve at all rather than serving
unauthenticated.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator

from fastapi import Header, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import new_session


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
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
