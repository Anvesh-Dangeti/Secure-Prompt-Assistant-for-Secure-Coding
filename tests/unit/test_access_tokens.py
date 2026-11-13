"""Per-developer access tokens: issued once, stored as a hash, scoped, expiring, revocable."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import cli
from app.access_tokens import (
    DISPLAY_CHARS, PREFIX, TokenError, create_token, hash_token, list_tokens, looks_like_token, resolve,
    revoke, state,
)
from app.db.models import AccessToken, Project, SourceType
from app.db.session import init_db, session_scope


@pytest.fixture(autouse=True)
def db() -> None:
    init_db()


def _issue(project: str = "demo", name: str = "dev-laptop", days: int | None = None):  # noqa: ANN202
    with session_scope() as s:
        return create_token(s, project, name, days)


def test_token_format_and_only_the_hash_is_stored() -> None:
    issued = _issue()
    assert issued.token.startswith(PREFIX) and looks_like_token(issued.token)
    assert len(issued.token) == len(PREFIX) + 43
    with session_scope() as s:
        row = s.scalars(select(AccessToken)).one()
        assert row.token_hash == hash_token(issued.token) and len(row.token_hash) == 64
        assert row.prefix == issued.token[:DISPLAY_CHARS]
        stored = " ".join(str(getattr(row, c.name)) for c in AccessToken.__table__.columns)
        assert issued.token not in stored
        project = s.get(Project, row.project_id)
        assert project.name == "demo" and project.source_type == SourceType.ZIP   # created on demand


def test_two_tokens_are_different() -> None:
    assert _issue(name="a").token != _issue(name="b").token


def test_resolve_valid_token_records_last_use() -> None:
    issued = _issue()
    with session_scope() as s:
        identity = resolve(s, issued.token)
    assert identity is not None and identity.project == "demo" and identity.name == "dev-laptop"
    with session_scope() as s:
        assert s.scalars(select(AccessToken)).one().last_used_at is not None


@pytest.mark.parametrize("presented", ["", "spa_pat_", "spa_pat_short", "x" * 51, "Bearer spa_pat_" + "a" * 43,
                                       "spa_pat_" + "a" * 42 + "!", "spa_pat_" + "a" * 43])
def test_malformed_or_unknown_tokens_resolve_to_nothing(presented: str) -> None:
    _issue()
    with session_scope() as s:
        assert resolve(s, presented) is None


def test_revoked_and_expired_tokens_stop_working() -> None:
    revoked, expired = _issue(name="r"), _issue(name="e")
    with session_scope() as s:
        revoke(s, revoked.id)
        s.get(AccessToken, expired.id).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    with session_scope() as s:
        assert resolve(s, revoked.token) is None and resolve(s, expired.token) is None
        assert {t.name: state(t) for t in list_tokens(s)} == {"r": "revoked", "e": "expired"}


def test_requests_are_validated() -> None:
    for kwargs, message in [({"project": "../evil"}, "project name"), ({"name": ""}, "token name"),
                            ({"name": "a\nb"}, "token name"), ({"days": 0}, "expiry"), ({"days": 5000}, "expiry")]:
        with pytest.raises(TokenError, match=message):
            _issue(**kwargs)
    with session_scope() as s, pytest.raises(TokenError, match="no token"):
        revoke(s, 999)


def test_a_token_reaches_an_existing_project_without_changing_it() -> None:
    with session_scope() as s:
        s.add(Project(name="portal", source_type=SourceType.ZIP))
    issued = _issue(project="portal")
    with session_scope() as s:
        assert len(s.scalars(select(Project)).all()) == 1
        assert resolve(s, issued.token).project == "portal"


def test_cli_shows_the_token_once_and_never_the_hash(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["token", "create", "--project", "demo", "--name", "ci", "--days", "7"]) == 0
    created = capsys.readouterr().out
    token = next(word for word in created.split() if word.startswith(PREFIX))
    assert "only time" in created
    assert cli.main(["token", "list"]) == 0
    listing = capsys.readouterr().out
    assert token not in listing and hash_token(token) not in listing
    assert token[:DISPLAY_CHARS] in listing and "active" in listing
    assert cli.main(["token", "revoke", "1"]) == 0
    capsys.readouterr()
    cli.main(["token", "list"])
    assert "revoked" in capsys.readouterr().out
    assert cli.main(["token", "create", "--project", "demo", "--name", "x", "--days", "0"]) == 2
