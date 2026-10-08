"""Every protected endpoint authenticates, and authentication fails closed."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import create_app
from tests._support import TEST_API_KEY


@pytest.fixture
def client() -> TestClient:
    with TestClient(create_app()) as c:
        yield c


def test_health_is_public_and_reveals_no_configuration(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["database"] == "ok"
    assert set(body["scanners"]) == {"semgrep", "bandit", "gitleaks", "pip-audit"}
    assert set(body["scanners"].values()) <= {"available", "missing"}   # no versions, no paths
    assert "limits" not in body and "version" not in body


def test_protected_route_without_key_is_401(client: TestClient) -> None:
    assert client.get("/api/v1/system/info").status_code == 401


def test_protected_route_with_wrong_key_is_401(client: TestClient) -> None:
    response = client.get("/api/v1/system/info", headers={"X-API-Key": TEST_API_KEY + "x"})
    assert response.status_code == 401


def test_protected_route_with_key_is_200(client: TestClient) -> None:
    response = client.get("/api/v1/system/info", headers={"X-API-Key": TEST_API_KEY})
    assert response.status_code == 200
    assert TEST_API_KEY not in response.text


def test_unconfigured_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_API_KEY", "")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        # Even a request carrying *some* key is refused when none is configured.
        assert c.get("/api/v1/system/info", headers={"X-API-Key": ""}).status_code == 503
        assert c.get("/api/v1/system/info").status_code == 503


def test_security_headers_present(client: TestClient) -> None:
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
