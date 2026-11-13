"""Per-developer access tokens for a shared server.

One shared ``SPA_API_KEY`` cannot tell developers apart, cannot be withdrawn
from one person, and opens every project. On a shared server it stays the
administrator's key, and each developer gets a token that:

* reaches **one project only** (least privilege; a token for another project
  sees 404s, so it cannot even learn which projects exist);
* **expires** (default 90 days) and can be **revoked** at once;
* is stored only as a **SHA-256 hash**. A slow password hash is unnecessary here:
  the token is 256 random bits, so there is nothing to guess offline;
* carries a recognisable ``spa_pat_`` prefix, so secret scanners and reviewers
  can spot one that was pasted somewhere it should not be.

The plaintext exists exactly once: in the return value of ``create_token``.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import AccessToken, Project, SourceType
from app.scan_service import InvalidRequest, get_or_create_project, validate_project_name

PREFIX = "spa_pat_"
# token_urlsafe(32) -> 43 characters of [A-Za-z0-9_-]
_TOKEN_RE = re.compile(r"^spa_pat_[A-Za-z0-9_-]{43}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,79}$")
DISPLAY_CHARS = 12          # "spa_pat_" + 4 characters: enough to tell tokens apart, useless to an attacker


class TokenError(ValueError):
    """The token request was refused. Message is safe to show."""


@dataclass(frozen=True)
class IssuedToken:
    id: int
    name: str
    project: str
    project_id: int
    expires_at: datetime
    token: str              # shown once, never stored


@dataclass(frozen=True)
class TokenIdentity:
    """Who a valid token belongs to -- everything the API needs, nothing secret."""

    id: int
    name: str
    project_id: int
    project: str
    expires_at: datetime


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def looks_like_token(text: str) -> bool:
    return bool(_TOKEN_RE.match(text))


def _aware(moment: datetime) -> datetime:
    # SQLite returns naive datetimes; every value written here is UTC.
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_token(session: Session, project_name: str, name: str, days: int | None = None) -> IssuedToken:
    """Issue a token for ``project_name`` (created as an upload project if it does not exist yet)."""
    try:
        validate_project_name(project_name)
    except InvalidRequest as exc:
        raise TokenError(str(exc)) from exc
    name = (name or "").strip()
    if not _NAME_RE.match(name):
        raise TokenError("token name must be 1-80 characters (letters, digits, space, '.', '_', '@', '-')")
    settings = get_settings()
    days = settings.token_default_days if days is None else days
    if not 1 <= days <= settings.token_max_days:
        raise TokenError(f"expiry must be between 1 and {settings.token_max_days} days")
    project = session.scalars(select(Project).where(Project.name == project_name)).first()
    if project is None:
        project = get_or_create_project(session, project_name, SourceType.ZIP, None)
    token = PREFIX + secrets.token_urlsafe(32)
    row = AccessToken(name=name, token_hash=hash_token(token), prefix=token[:DISPLAY_CHARS],
                      project_id=project.id, expires_at=_now() + timedelta(days=days))
    session.add(row)
    session.flush()
    return IssuedToken(row.id, row.name, project.name, project.id, _aware(row.expires_at), token)


def resolve(session: Session, presented: str) -> TokenIdentity | None:
    """The identity behind ``presented``, or None if it is malformed, unknown, revoked or expired."""
    if not looks_like_token(presented):
        return None          # junk never reaches the database
    row = session.scalars(select(AccessToken).where(AccessToken.token_hash == hash_token(presented))).first()
    if row is None or row.revoked_at is not None:
        return None
    now = _now()
    if _aware(row.expires_at) <= now:
        return None
    row.last_used_at = now
    return TokenIdentity(row.id, row.name, row.project_id, row.project.name, _aware(row.expires_at))


def list_tokens(session: Session) -> list[AccessToken]:
    return list(session.scalars(select(AccessToken).order_by(AccessToken.id)))


def revoke(session: Session, token_id: int) -> AccessToken:
    row = session.get(AccessToken, token_id)
    if row is None:
        raise TokenError(f"no token #{token_id}")
    if row.revoked_at is None:
        row.revoked_at = _now()
    return row


def state(row: AccessToken) -> str:
    if row.revoked_at is not None:
        return "revoked"
    return "expired" if _aware(row.expires_at) <= _now() else "active"
