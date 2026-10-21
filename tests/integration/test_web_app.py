"""The web interface end to end: every page with real data, and the developer-mode loop through its forms."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select

from app import pipeline
from app.db.models import LifecycleState, TrackedFinding
from app.db.session import init_db, session_scope
from dashboard.web import security
from tests._verify_support import SQL_FIXED, SQL_VULNERABLE, TOY_APP, scan, scanners, write_app
from tests._web_support import HTMX, client, csrf, post, signed_in

PAGES = {"": "Overview", "/findings": "Findings", "/prompt": "Prompt &amp; lint", "/verify": "Verify a fix",
         "/history": "Scan history"}


@pytest.fixture(autouse=True)
def stand_in_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "FAILURE_DELAY_S", 0.0)
    monkeypatch.setattr(pipeline, "all_scanners", scanners)
    init_db()


@pytest.fixture
def code(tmp_path: Path) -> Path:
    root = write_app(tmp_path / "code")
    scan("demo", root)
    return root


def _tracked(rule: str) -> TrackedFinding:
    with session_scope() as s:
        row = s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == rule)).first()
        s.expunge(row)
        return row


# ---- pages ---------------------------------------------------------------------------------


def test_every_page_renders_with_real_data(code: Path) -> None:
    c = signed_in()
    assert c.get("/").headers["location"] == "/p/1"
    for suffix, title in PAGES.items():
        response = c.get(f"/p/1{suffix}")
        assert response.status_code == 200 and title in response.text, suffix
    overview = c.get("/p/1").text
    assert "Open findings by OWASP category" in overview and "<svg" in overview and "B602" not in overview
    b602 = _tracked("B602")
    detail = c.get(f"/p/1/findings/{b602.id}").text
    assert "subprocess" in detail and "Scanner evidence" in detail


def test_with_no_project_the_start_page_offers_a_scan() -> None:
    c = signed_in()
    response = c.get("/")
    assert response.status_code == 200 and 'action="/scan"' in response.text


def test_findings_filter_returns_a_fragment_for_htmx(code: Path) -> None:
    c = signed_in()
    full = c.get("/p/1/findings")
    assert "<html" in full.text and "B602" in full.text                       # open states by default
    fragment = c.get("/p/1/findings?filtered=1&state=RESOLVED&state=BOGUS", headers=HTMX)
    assert "<html" not in fragment.text and "0 of 3 tracked findings" in fragment.text
    bandit = c.get("/p/1/findings?filtered=1&tool=bandit&tool=nonexistent", headers=HTMX).text
    assert "B602" in bandit and "tainted-sql-string" not in bandit


def test_a_new_project_is_scanned_through_the_form(code: Path) -> None:
    c = signed_in()
    plain = post(c, "/scan", {"name": "second", "path": str(code), "label": "first look"}, htmx=False)
    assert plain.status_code == 303 and plain.headers["location"] == "/p/2"
    assert "Scan #2 finished" in c.get("/p/2").text                           # the one-time notice
    assert "Scan #2 finished" not in c.get("/p/2").text
    via_htmx = post(c, "/p/2/scan", {"path": str(code)})
    assert via_htmx.status_code == 200 and via_htmx.headers["HX-Redirect"] == "/p/2"


def test_a_refused_action_says_why(code: Path) -> None:
    c = signed_in()
    response = post(c, "/p/1/prompt", {"finding": str(_tracked("B602").id), "strategy": "S7", "path": "relative/path"})
    assert response.status_code == 422 and "No prompt was built." in response.text and "absolute path" in response.text
    assert post(c, "/scan", {"name": "bad name!", "path": str(code)}).status_code == 422


def test_a_finding_is_only_reachable_through_its_own_project(code: Path, tmp_path: Path) -> None:
    scan("other", write_app(tmp_path / "other"))
    c = signed_in()
    with session_scope() as s:
        foreign = s.scalars(select(TrackedFinding.id).where(TrackedFinding.project_id == 2)).first()
    assert c.get(f"/p/1/findings/{foreign}").status_code == 404
    assert post(c, "/p/1/prompt", {"finding": str(foreign), "path": str(code)}).status_code == 404
    assert c.get(f"/p/2/findings/{foreign}").status_code == 200


# ---- the developer-mode loop ----------------------------------------------------------------------


def test_the_developer_loop_in_the_browser(code: Path) -> None:
    c = signed_in()
    sqli = _tracked("B608").id

    built = post(c, "/p/1/prompt", {"finding": str(sqli), "strategy": "S7", "path": str(code)})
    assert built.status_code == 200 and "get_user" in built.text and "Lint of this prompt" in built.text
    assert "✓</span>PASS" in built.text and 'data-copy="prompt-text"' in built.text

    shortened = post(c, "/p/1/lint", {"finding": str(sqli), "text": "Fix the SQL injection in app.py.",
                                      "bound": "true", "fix": "false"})                 # path: remembered checkout
    assert "✕</span>FAIL" in shortened.text and "MISSING" in shortened.text
    fixed = post(c, "/p/1/lint", {"finding": str(sqli), "text": "Fix the SQL injection in app.py.",
                                  "bound": "true", "fix": "true"})
    assert "With fix-its applied" in fixed.text and fixed.text.count("✓</span>PASS") == 1

    write_app(code, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))                  # the developer's assistant fixed it
    verified = post(c, "/p/1/verify", {"finding": str(sqli), "how": "rescan", "path": str(code)})
    assert verified.status_code == 200 and "verdict VERIFIED_RESOLVED" in verified.text
    assert "developer mode never executes repository code" in verified.text
    assert "VERIFIED_RESOLVED" in c.get(f"/p/1/findings/{sqli}").text
    history = c.get("/p/1/history").text
    assert "verify #" in history and "#2" in history


def test_judge_the_latest_scan(code: Path) -> None:
    write_app(code, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))
    scan("demo", code)
    c = signed_in()
    response = post(c, "/p/1/verify", {"finding": str(_tracked("B608").id), "how": "latest"})
    assert "Latest scan judged → verdict VERIFIED_RESOLVED" in response.text


def test_suppression_needs_a_reason_and_can_be_withdrawn(code: Path) -> None:
    c = signed_in()
    b602 = _tracked("B602").id
    refused = post(c, f"/p/1/findings/{b602}/suppress", {"reason": "x"})
    assert refused.status_code == 422 and "reason" in refused.text
    assert post(c, f"/p/1/findings/{b602}/suppress", {"reason": "accepted risk: internal tool"}).status_code == 200
    assert _tracked("B602").status == LifecycleState.SUPPRESSED
    assert "accepted risk: internal tool" in c.get(f"/p/1/findings/{b602}").text
    post(c, f"/p/1/findings/{b602}/unsuppress")
    assert _tracked("B602").status != LifecycleState.SUPPRESSED


def test_sign_out_ends_the_session(code: Path) -> None:
    c = signed_in()
    response = c.post("/logout", data={"csrf": csrf(c, "/new")})
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert c.get("/p/1").status_code == 303


def test_unknown_project_is_a_404_page(code: Path) -> None:
    response = signed_in().get("/p/999")
    assert response.status_code == 404 and "Not found." in response.text


def test_the_server_binds_loopback_only() -> None:
    from dashboard.web import __main__ as entry

    assert entry.HOST == "127.0.0.1"
    assert client(peer="0.0.0.0").get("/login").status_code == 403
