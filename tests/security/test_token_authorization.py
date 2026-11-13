"""A developer's token reaches its own project and nothing else (stand-in scanners, no model).

Another project's data answers 404 -- exactly like data that does not exist --
so a token cannot even learn which projects a shared server holds.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import pipeline
from app.access_tokens import create_token, revoke
from app.core.config import get_settings
from app.db.models import AccessToken, Project, Scan, TrackedFinding
from app.db.session import init_db, session_scope
from app.main import create_app
from tests._support import TEST_API_KEY
from tests._verify_support import TOY_APP, scan, scanners, write_app

ADMIN = {"X-API-Key": TEST_API_KEY}


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    """Two scanned projects and one token for the first."""
    monkeypatch.setattr(pipeline, "all_scanners", scanners)
    init_db()
    scan("alpha", write_app(tmp_path / "alpha"))
    scan("beta", write_app(tmp_path / "beta"))
    with session_scope() as s:
        token = create_token(s, "alpha", "dev").token
        ids = {}
        for name in ("alpha", "beta"):
            project = s.scalars(select(Project).where(Project.name == name)).one()
            ids[name] = {
                "project": project.id,
                "scan": s.scalars(select(Scan.id).where(Scan.project_id == project.id)).first(),
                "tracked": s.scalars(select(TrackedFinding.id).where(TrackedFinding.project_id == project.id)
                                     ).first(),
            }
    return {"token": token, "auth": {"Authorization": f"Bearer {token}"}, **ids}


@pytest.fixture
def client() -> TestClient:
    with TestClient(create_app()) as c:
        yield c


def _routes(ids: dict) -> list[tuple[str, str, dict]]:
    p, s, t = ids["project"], ids["scan"], ids["tracked"]
    return [
        ("GET", f"/api/v1/projects/{p}/scans", {}),
        ("GET", f"/api/v1/projects/{p}/findings", {}),
        ("GET", f"/api/v1/scans/{s}", {}),
        ("GET", f"/api/v1/scans/{s}/findings", {}),
        ("GET", f"/api/v1/tracked/{t}", {}),
        ("GET", f"/api/v1/tracked/{t}/verifications", {}),
        ("POST", f"/api/v1/tracked/{t}/prompt", {"json": {"file_path": "app.py", "content": TOY_APP}}),
        ("POST", f"/api/v1/tracked/{t}/suppress", {"json": {"reason": "accepted risk"}}),
        ("POST", f"/api/v1/tracked/{t}/unsuppress", {}),
        ("POST", f"/api/v1/tracked/{t}/verify", {}),
        ("POST", f"/api/v1/projects/{p}/scans/git", {"json": {}}),
        ("POST", f"/api/v1/projects/{p}/scans/zip", {"files": {"archive": ("a.zip", b"PK", "application/zip")}}),
    ]


def test_another_projects_data_is_not_found(client: TestClient, world: dict) -> None:
    for method, url, kw in _routes(world["beta"]):
        response = client.request(method, url, headers=world["auth"], **kw)
        assert response.status_code == 404, (method, url, response.text)
        assert "beta" not in response.text


def test_own_projects_data_is_reachable(client: TestClient, world: dict) -> None:
    # Refused on content, not on access: one scan only (nothing to verify against), no URL, a broken archive.
    expected = {"/verify": 409, "/scans/git": 400, "/scans/zip": 400}
    for method, url, kw in _routes(world["alpha"]):
        response = client.request(method, url, headers=world["auth"], **kw)
        want = next((code for suffix, code in expected.items() if url.endswith(suffix)), 200)
        assert response.status_code == want, (method, url, response.text)


def test_listing_shows_only_the_tokens_project(client: TestClient, world: dict) -> None:
    assert [p["name"] for p in client.get("/api/v1/projects", headers=world["auth"]).json()] == ["alpha"]
    assert len(client.get("/api/v1/projects", headers=ADMIN).json()) == 2


def test_whoami_names_the_project_and_never_the_token(client: TestClient, world: dict) -> None:
    body = client.get("/api/v1/whoami", headers=world["auth"])
    assert body.status_code == 200
    assert body.json()["kind"] == "token" and body.json()["project"] == "alpha"
    assert world["token"] not in body.text
    assert client.get("/api/v1/whoami", headers=ADMIN).json()["kind"] == "admin"


def test_a_token_cannot_do_administrator_things(client: TestClient, world: dict) -> None:
    assert client.post("/api/v1/projects", json={"name": "new"}, headers=world["auth"]).status_code == 403
    assert client.get("/api/v1/system/info", headers=world["auth"]).status_code == 401
    assert client.post("/api/v1/projects", json={"name": "new"}, headers=ADMIN).status_code == 201


def test_verifying_against_another_projects_scan_is_refused(client: TestClient, world: dict) -> None:
    url = f"/api/v1/tracked/{world['alpha']['tracked']}/verify?scan_id={world['beta']['scan']}"
    assert client.post(url, headers=world["auth"]).status_code == 404


def test_the_narrowest_credential_wins(client: TestClient, world: dict) -> None:
    both = {**ADMIN, **world["auth"]}
    assert client.get(f"/api/v1/projects/{world['beta']['project']}/scans", headers=both).status_code == 404


@pytest.mark.parametrize("header", ["Bearer spa_pat_" + "a" * 43, "Bearer nonsense", "Bearer ", "Basic abc"])
def test_bad_bearer_tokens_are_401(client: TestClient, world: dict, header: str) -> None:
    response = client.get("/api/v1/whoami", headers={"Authorization": header})
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_revoked_and_expired_tokens_are_401(client: TestClient, world: dict) -> None:
    with session_scope() as s:
        expired = create_token(s, "alpha", "old")
        s.get(AccessToken, expired.id).expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        revoke(s, 1)
    for token in (world["token"], expired.token):
        assert client.get("/api/v1/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_tokens_work_without_an_administrator_key(world: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_API_KEY", "")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        assert c.get("/api/v1/whoami", headers=world["auth"]).status_code == 200
        assert c.get("/api/v1/whoami").status_code == 503          # the key path still fails closed


def test_the_token_never_reaches_responses_or_logs(client: TestClient, world: dict,
                                                    caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    bodies = [client.request(m, u, headers=world["auth"], **kw).text for m, u, kw in _routes(world["alpha"])]
    bodies.append(client.get("/api/v1/whoami", headers=world["auth"]).text)
    assert all(world["token"] not in body for body in bodies)
    assert world["token"] not in caplog.text
