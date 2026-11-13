"""Prompts over HTTP: the connector sends the finding's one file; nothing else is accepted or kept."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import pipeline
from app.access_tokens import create_token
from app.core.config import get_settings
from app.db.models import TrackedFinding
from app.db.session import init_db, session_scope
from app.main import create_app
from tests._support import TEST_API_KEY
from tests._verify_support import SQL_FIXED, SQL_VULNERABLE, TOY_APP, scan, scanners, write_app


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, dict, str]:
    monkeypatch.setattr(pipeline, "all_scanners", scanners)
    init_db()
    scan("demo", write_app(tmp_path / "code"))
    with session_scope() as s:
        token = create_token(s, "demo", "dev").token
        tracked = s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == "B608")).one().id
    with TestClient(create_app()) as client:
        yield client, {"Authorization": f"Bearer {token}"}, f"/api/v1/tracked/{tracked}/prompt"


def test_the_findings_file_gives_a_linted_prompt(setup: tuple[TestClient, dict, str]) -> None:
    client, auth, url = setup
    response = client.post(url, headers=auth, json={"file_path": "app.py", "content": TOY_APP})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["strategy"] == "S7" and body["file_path"] == "app.py" and body["warning"] is None
    assert body["lint"]["passed"] is True and body["tokens"] > 0
    assert SQL_VULNERABLE in body["prompt"]                          # the flagged line is in the context
    assert "def ping_host" not in body["prompt"]                      # the rest of the file is not


def test_strategy_names_are_case_insensitive_and_checked(setup: tuple[TestClient, dict, str]) -> None:
    client, auth, url = setup
    ok = client.post(url, headers=auth, json={"strategy": "s7m", "file_path": "app.py", "content": TOY_APP})
    assert ok.status_code == 200 and ok.json()["strategy"] == "S7m"
    bad = client.post(url, headers=auth, json={"strategy": "S99", "file_path": "app.py", "content": TOY_APP})
    assert bad.status_code == 400 and "unknown strategy" in bad.text


@pytest.mark.parametrize("path", ["other.py", "../app.py", "/etc/passwd", "C:\\app.py", "./app.py", "APP.py"])
def test_only_the_findings_own_path_is_accepted(setup: tuple[TestClient, dict, str], path: str) -> None:
    client, auth, url = setup
    response = client.post(url, headers=auth, json={"file_path": path, "content": TOY_APP})
    assert response.status_code == 400 and "app.py" in response.json()["detail"]


def test_an_oversized_file_is_refused(setup: tuple[TestClient, dict, str], monkeypatch: pytest.MonkeyPatch) -> None:
    client, auth, url = setup
    monkeypatch.setenv("SPA_MAX_CONTEXT_FILE_BYTES", "2048")
    get_settings.cache_clear()
    content = TOY_APP + "#" * 4096
    assert client.post(url, headers=auth, json={"file_path": "app.py", "content": content}).status_code == 413


def test_a_changed_file_is_flagged(setup: tuple[TestClient, dict, str]) -> None:
    client, auth, url = setup
    changed = TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED)
    body = client.post(url, headers=auth, json={"file_path": "app.py", "content": changed}).json()
    assert body["warning"] and "rescan" in body["warning"]


def test_nothing_is_left_in_scratch(setup: tuple[TestClient, dict, str]) -> None:
    client, auth, url = setup
    client.post(url, headers=auth, json={"file_path": "app.py", "content": TOY_APP})
    client.post(url, headers=auth, json={"file_path": "app.py", "content": ""})   # empty file: refused, cleaned
    leftovers = [p.name for p in get_settings().scratch_root.iterdir() if p.name.startswith("prompt-")]
    assert leftovers == []


def test_the_administrator_key_works_too(setup: tuple[TestClient, dict, str]) -> None:
    client, _auth, url = setup
    response = client.post(url, headers={"X-API-Key": TEST_API_KEY}, json={"file_path": "app.py", "content": TOY_APP})
    assert response.status_code == 200
