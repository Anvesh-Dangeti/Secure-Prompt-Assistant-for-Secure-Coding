"""A developer on another machine, end to end: the real ``spa`` commands against a real HTTP server.

The server runs in a thread on a free loopback port. With stand-in scanners the
whole loop runs everywhere -- connect, scan, findings, prompt, fix, verify,
another project's token, revocation, disconnect. With the real scanners
installed, one more test uploads the seeded fixture and expects every finding.
"""

from __future__ import annotations

import io
import json
import shutil
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from sqlalchemy import select

from app import pipeline
from app.access_tokens import create_token, revoke
from app.db.models import TrackedFinding
from app.db.session import init_db, session_scope
from app.main import create_app
from app.scanners import all_scanners
from spa_connect import cli as spa
from tests._verify_support import SQL_FIXED, SQL_VULNERABLE, TOY_APP, scanners, write_app

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "flask_vuln_app"


@pytest.fixture
def server() -> Iterator[str]:
    init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(create_app(), log_level="warning", lifespan="on"))
    thread = threading.Thread(target=srv.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not srv.started:
        if time.monotonic() > deadline:
            raise RuntimeError("test server did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    thread.join(timeout=10)
    sock.close()


@pytest.fixture(autouse=True)
def client_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "developer-config"
    monkeypatch.setenv("SPA_CONFIG_DIR", str(home))
    monkeypatch.delenv("SPA_TOKEN", raising=False)
    return home


def _token(project: str, name: str = "laptop") -> tuple[int, str]:
    with session_scope() as s:
        issued = create_token(s, project, name)
    return issued.id, issued.token


def _spa(folder: Path, *args: str, stdin: str | None = None, monkeypatch: pytest.MonkeyPatch | None = None) -> int:
    if stdin is not None and monkeypatch is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin + "\n"))
    return spa.main(["--dir", str(folder), *args])


def _tracked(rule: str) -> int:
    with session_scope() as s:
        return s.scalars(select(TrackedFinding.id).where(TrackedFinding.rule_id == rule)).first()


def test_connect_scan_prompt_fix_verify(server: str, tmp_path: Path, client_home: Path,
                                        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(pipeline, "all_scanners", scanners)
    token_id, token = _token("helpdesk-portal")
    project = write_app(tmp_path / "helpdesk-portal")
    (project / ".env").write_text("DB_PASSWORD=live-secret\n", encoding="utf-8")

    # connect: the token is checked by the server, kept outside the project, absent from the link
    assert _spa(project, "connect", "--server", server, "--project", "helpdesk-portal", "--token-stdin",
                stdin=token, monkeypatch=monkeypatch) == 0
    assert "Connected" in capsys.readouterr().out
    link = json.loads((project / ".spa" / "connection.json").read_text(encoding="utf-8"))
    assert link["project"] == "helpdesk-portal" and token not in json.dumps(link)
    assert token in (client_home / "credentials.json").read_text(encoding="utf-8")

    # scan, from a sub-folder: the link is found upwards; the local .env is not sent
    (project / "sub").mkdir()
    assert _spa(project / "sub", "scan", "--label", "before the fix") == 0
    out = capsys.readouterr().out
    assert "status COMPLETED" in out and "not sent (local secret files): .env" in out

    assert _spa(project, "findings") == 0
    out = capsys.readouterr().out
    target = _tracked("B608")
    assert f"{target}  " in out and "app.py:" in out

    # prompt: only app.py is sent; the prompt carries the flagged line
    assert _spa(project, "prompt", str(target), "--strategy", "S7m", "-o", str(tmp_path / "prompt.txt")) == 0
    err = capsys.readouterr().err
    assert "[S7m] lint PASS" in err
    assert SQL_VULNERABLE in (tmp_path / "prompt.txt").read_text(encoding="utf-8")

    # the developer's assistant fixes it; verify rescans and judges
    write_app(project, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))
    assert _spa(project, "verify", str(target)) == 0
    assert "VERIFIED_RESOLVED" in capsys.readouterr().out

    # a token for another project cannot see this one
    _other_id, other_token = _token("other-app", "someone-else")
    elsewhere = write_app(tmp_path / "other-app")
    assert _spa(elsewhere, "connect", "--server", server, "--token-stdin", stdin=other_token,
                monkeypatch=monkeypatch) == 0
    capsys.readouterr()
    assert _spa(elsewhere, "prompt", str(target)) == 2
    assert "not found" in capsys.readouterr().err

    # a revoked token stops working at once
    with session_scope() as s:
        revoke(s, token_id)
    assert _spa(project, "findings") == 2
    assert "refused the token" in capsys.readouterr().err

    assert _spa(project, "disconnect") == 0
    assert not (project / ".spa").exists()
    assert token not in (client_home / "credentials.json").read_text(encoding="utf-8")


def test_a_token_for_another_project_is_refused_at_connect(server: str, tmp_path: Path,
                                                            monkeypatch: pytest.MonkeyPatch,
                                                            capsys: pytest.CaptureFixture[str]) -> None:
    _id, token = _token("portal")
    folder = write_app(tmp_path / "x")
    assert _spa(folder, "connect", "--server", server, "--project", "billing", "--token-stdin", stdin=token,
                monkeypatch=monkeypatch) == 2
    assert "for project 'portal'" in capsys.readouterr().err
    assert not (folder / ".spa").exists()


def test_an_unknown_token_is_refused_at_connect(server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                capsys: pytest.CaptureFixture[str]) -> None:
    folder = write_app(tmp_path / "x")
    assert _spa(folder, "connect", "--server", server, "--token-stdin", stdin="spa_pat_" + "Z" * 43,
                monkeypatch=monkeypatch) == 2
    assert "refused the token" in capsys.readouterr().err


@pytest.mark.scanners
@pytest.mark.skipif(not all(s.is_available() for s in all_scanners()), reason="scanners not installed")
def test_the_seeded_fixture_through_the_connector(server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                  capsys: pytest.CaptureFixture[str]) -> None:
    _id, token = _token("flask-vuln-app")
    project = tmp_path / "flask_vuln_app"
    shutil.copytree(FIXTURE, project, ignore=shutil.ignore_patterns("__pycache__"))
    assert _spa(project, "connect", "--server", server, "--token-stdin", stdin=token, monkeypatch=monkeypatch) == 0
    assert _spa(project, "scan") == 0
    out = capsys.readouterr().out
    assert "status COMPLETED" in out and "findings: 24" in out
