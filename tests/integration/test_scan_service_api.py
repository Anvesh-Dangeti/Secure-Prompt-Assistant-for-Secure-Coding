"""Scan service + API end-to-end: upload, persist, read back; refusals are clean."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.cli import zip_directory
from app.core.scratch import scratch_dir
from app.db.models import Finding, Scan, ScannerRun
from app.db.session import init_db, session_scope
from app.main import create_app
from app.scan_service import InvalidRequest, scan_git, scan_zip
from app.scanners import all_scanners
from tests._support import TEST_API_KEY

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "flask_vuln_app"
FIXTURE_SECRET = "sk_test_4eC39HqLyjWDarjtT1zdp7dcFAKE00"
needs_scanners = pytest.mark.skipif(not all(s.is_available() for s in all_scanners()),
                                    reason="scanners not installed")
AUTH = {"X-API-Key": TEST_API_KEY}


@pytest.fixture
def client() -> TestClient:
    with TestClient(create_app()) as c:
        yield c


def _fixture_zip_bytes() -> bytes:
    with scratch_dir("zipbytes-") as work:
        zip_directory(FIXTURE, work / "f.zip")
        return (work / "f.zip").read_bytes()


@needs_scanners
@pytest.mark.scanners
def test_zip_scan_is_persisted_without_secrets() -> None:
    init_db()
    with scratch_dir("svc-") as work:
        zip_directory(FIXTURE, work / "f.zip")
        summary = scan_zip("fixture", work / "f.zip", label="baseline")
    assert summary.status == "COMPLETED"
    assert summary.findings == 24
    with session_scope() as s:
        scan = s.get(Scan, summary.scan_id)
        assert scan.source_ref and len(scan.source_ref) == 64
        runs = s.scalars(select(ScannerRun).where(ScannerRun.scan_id == scan.id)).all()
        assert {r.tool: r.status.value for r in runs} == {
            "semgrep": "OK", "bandit": "OK", "gitleaks": "OK", "pip-audit": "OK"}
        findings = s.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
        assert len(findings) == 24
        for f in findings:
            assert FIXTURE_SECRET not in f.snippet + f.message


def test_unsafe_url_creates_no_rows() -> None:
    init_db()
    with pytest.raises(InvalidRequest):
        scan_git("ssrf", "https://169.254.169.254/latest/meta-data")
    with session_scope() as s:
        assert s.scalars(select(Scan)).all() == []


def test_refused_archive_is_recorded_as_failed_scan() -> None:
    init_db()
    with scratch_dir("svc-") as work:
        archive = work / "evil.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../../escape.py", "x = 1\n")
        summary = scan_zip("evil", archive)
    assert summary.status == "FAILED"
    assert "traversal" in (summary.error or "")


def test_api_requires_key_for_every_project_route(client: TestClient) -> None:
    for method, path in [("get", "/api/v1/projects"), ("post", "/api/v1/projects"),
                         ("get", "/api/v1/scans/1"), ("get", "/api/v1/scans/1/findings"),
                         ("post", "/api/v1/projects/1/scans/zip"), ("post", "/api/v1/projects/1/scans/git")]:
        response = getattr(client, method)(path, **({"json": {}} if method == "post" else {}))
        assert response.status_code == 401, (method, path)


def test_api_rejects_ssrf_url_on_project_creation(client: TestClient) -> None:
    response = client.post("/api/v1/projects", json={"name": "p", "repo_url": "http://127.0.0.1/a/b"},
                           headers=AUTH)
    assert response.status_code == 400


def test_api_upload_size_limit(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import get_settings

    project = client.post("/api/v1/projects", json={"name": "big"}, headers=AUTH).json()
    monkeypatch.setenv("SPA_MAX_UPLOAD_BYTES", "2048")
    get_settings.cache_clear()
    payload = io.BytesIO(b"PK\x03\x04" + b"\x00" * 200_000)
    response = client.post(f"/api/v1/projects/{project['id']}/scans/zip", headers=AUTH,
                           files={"archive": ("big.zip", payload, "application/zip")})
    assert response.status_code == 413


def test_api_rejects_zip_slip_upload(client: TestClient) -> None:
    project = client.post("/api/v1/projects", json={"name": "slip"}, headers=AUTH).json()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("../../../escape.py", "x = 1\n")
    response = client.post(f"/api/v1/projects/{project['id']}/scans/zip", headers=AUTH,
                           files={"archive": ("slip.zip", buffer.getvalue(), "application/zip")})
    assert response.status_code == 400
    assert "traversal" in response.json()["detail"]


@needs_scanners
@pytest.mark.scanners
def test_api_zip_scan_round_trip(client: TestClient) -> None:
    project = client.post("/api/v1/projects", json={"name": "api-fixture"}, headers=AUTH).json()
    response = client.post(f"/api/v1/projects/{project['id']}/scans/zip", headers=AUTH,
                           files={"archive": ("fixture.zip", _fixture_zip_bytes(), "application/zip")})
    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["status"] == "COMPLETED" and summary["findings"] == 24
    findings = client.get(f"/api/v1/scans/{summary['scan_id']}/findings?in_scope_only=true", headers=AUTH).json()
    assert len(findings) == 24   # all in scope; B403/B404 are in-scope false positives
    assert all(FIXTURE_SECRET not in f["snippet"] for f in findings)
