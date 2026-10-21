"""Web interface security: who may connect, sign-in, CSRF, headers, and scanned content rendered only as text.

A repository under scan controls its file names and code, and its code shapes
scanner messages and rule matches. All of that reaches these pages. The tests
seed hostile text through the real scan path and check that it is shown -- as
escaped text -- and never becomes markup, a link, a script or an attribute.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path

import pytest

from app import pipeline
from app.core.config import get_settings
from app.db.models import TrackedFinding
from app.db.session import init_db, session_scope
from dashboard import actions, data
from dashboard.web import render, security
from dashboard.web.app import create_web_app
from tests._support import TEST_API_KEY
from tests._verify_support import PatternScanner, scanners, write_app
from tests._verify_support import scan as scan_code
from tests._web_support import HTMX, client, csrf, post, sign_in, signed_in

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "dashboard" / "web"
HTMX_FILE = WEB / "static" / "htmx-2.0.4.min.js"
HTMX_SHA256 = "e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447"   # htmx.org@2.0.4 dist/htmx.min.js

PAYLOAD = '<img src=x onerror=alert(1)> <script>alert(2)</script> ![pixel](https://attacker.example/p.png)'
EVIL_FILE = "x'onmouseover=alert(3).py"     # Windows forbids < > " in names; a single quote still tries to break out


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "FAILURE_DELAY_S", 0.0)
    init_db()


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(pipeline, "all_scanners", scanners)
    code = write_app(tmp_path / "code")
    scan_code("demo", code)
    return code


def _pages(project_id: int = 1, tracked_id: int = 1) -> list[str]:
    base = f"/p/{project_id}"
    return [base, f"{base}/findings", f"{base}/findings/{tracked_id}", f"{base}/prompt", f"{base}/verify",
            f"{base}/history", "/new"]


def _assert_headers(response) -> None:  # noqa: ANN001
    for name, value in security.HEADERS.items():
        assert response.headers.get(name) == value, (response.request.url, name)


# ---- who may connect --------------------------------------------------------------------


@pytest.mark.parametrize("url", ["/login", "/", "/p/1", "/static/app.css", "/static/htmx-2.0.4.min.js"])
def test_a_peer_off_this_machine_is_refused_everywhere(url: str) -> None:
    response = client(peer="192.168.1.20").get(url)
    assert response.status_code == 403 and "only serves this machine" in response.text
    _assert_headers(response)


@pytest.mark.parametrize("host", ["attacker.example", "attacker.example:8080", "127.0.0.1.attacker.example",
                                  "localhost.attacker.example:8080", ""])
def test_a_foreign_host_header_is_refused(host: str) -> None:
    # DNS rebinding: a hostile page whose name resolves to 127.0.0.1 still sends its own name as Host.
    response = client().get("/login", headers={"host": host})
    assert response.status_code == 400


@pytest.mark.parametrize("host", ["127.0.0.1:8080", "localhost:8080", "[::1]:8080", "LOCALHOST"])
def test_loopback_names_are_accepted(host: str) -> None:
    assert client(peer="::1").get("/login", headers={"host": host}).status_code == 200


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS"])
def test_only_get_head_and_post_are_served(method: str) -> None:
    assert client().request(method, "/login").status_code == 405


def test_bodies_must_be_declared_and_small() -> None:
    c = client()
    too_big = c.post("/login", content=b"x", headers={"content-length": str(security.MAX_BODY_BYTES + 1),
                                                        "content-type": "application/x-www-form-urlencoded"})
    assert too_big.status_code == 413
    chunked = c.post("/login", content=iter([b"key=x"]), headers={"content-type": "application/x-www-form-urlencoded"})
    assert chunked.status_code == 411


# ---- headers --------------------------------------------------------------------------------


def test_every_kind_of_response_carries_the_security_headers(project: Path) -> None:
    c = signed_in()
    for response in (c.get("/login"), c.get("/p/1"), c.get("/static/app.css"), c.get("/p/999"),
                     client(peer="10.0.0.1").get("/login"), client().get("/p/1")):
        _assert_headers(response)
    assert "'unsafe-inline'" not in security.CSP and "'unsafe-eval'" not in security.CSP
    assert "script-src 'self'" in security.CSP and "frame-ancestors 'none'" in security.CSP


def test_the_referrer_policy_keeps_a_real_origin_on_our_own_posts() -> None:
    # Found with a real browser: under "no-referrer" Chromium sends "Origin: null" on same-origin
    # form posts, which the cross-site check (correctly) refuses -- signing in became impossible.
    assert security.HEADERS["Referrer-Policy"] == "same-origin"
    assert '<meta name="referrer" content="same-origin">' in (WEB / "templates" / "_head.html").read_text("utf-8")


def test_a_crash_shows_no_detail_and_keeps_the_headers(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    c = signed_in()

    def boom(_project_id: int) -> None:
        raise RuntimeError(r"C:\secret\path leaked")

    monkeypatch.setattr(data, "overview", boom)
    response = c.get("/p/1")
    assert response.status_code == 500 and "secret" not in response.text and "Traceback" not in response.text
    _assert_headers(response)


def test_no_api_docs_are_served(project: Path) -> None:
    c = signed_in()
    for url in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(url).status_code == 404


# ---- sign-in --------------------------------------------------------------------------------


def test_every_page_needs_a_session(project: Path) -> None:
    c = client()
    for url in _pages():
        response = c.get(url)
        assert response.status_code == 303 and response.headers["location"] == "/login", url
        partial = c.get(url, headers=HTMX)
        assert partial.status_code == 401 and partial.headers["HX-Redirect"] == "/login", url


def test_sign_in_needs_the_right_key_and_a_csrf_token() -> None:
    c = client()
    assert c.post("/login", data={"key": TEST_API_KEY}).status_code == 403          # no token
    assert sign_in(c, "wrong").status_code == 401
    assert c.get("/new").status_code == 303                                            # still signed out
    assert sign_in(c).status_code == 303 and c.get("/new").status_code == 200


def test_sign_in_starts_a_fresh_session() -> None:
    c = client()
    before = csrf(c)
    sign_in(c)
    assert csrf(c, "/new") != before


def test_the_session_cookie_is_httponly_and_same_site_strict() -> None:
    c = client()
    cookie = c.get("/login").headers["set-cookie"].lower()
    assert cookie.startswith(f"{security.SESSION_COOKIE}=") and "httponly" in cookie and "samesite=strict" in cookie


def test_five_wrong_keys_lock_sign_in_for_everyone() -> None:
    app = create_web_app()
    attacker, other = client(app), client(app)
    token = csrf(other)                                       # the locked page has no form, so take it first
    for attempt in range(security.MAX_FAILURES):
        assert sign_in(attacker, f"wrong-{attempt}").status_code == 401
    assert "Too many wrong keys" in attacker.get("/login").text
    fresh = client(app)                                       # a new cookie does not reset the lockout
    assert "Too many wrong keys" in fresh.get("/login").text and 'name="key"' not in fresh.get("/login").text
    assert other.post("/login", data={"key": TEST_API_KEY, "csrf": token}).status_code == 429   # even the right key
    assert other.get("/new").status_code == 303
    assert fresh.get("/new").status_code == 303


def test_lockout_shows_at_once_not_one_request_late() -> None:
    c = client()
    for attempt in range(security.MAX_FAILURES - 1):
        sign_in(c, f"wrong-{attempt}")
    last = sign_in(c, "wrong-last")
    assert "Too many wrong keys" in last.text and 'name="key"' not in last.text


def test_no_key_configured_means_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    c = client()
    token = csrf(c)                                           # the disabled page has no form
    monkeypatch.setenv("SPA_API_KEY", "")
    get_settings.cache_clear()
    page = c.get("/login")
    assert "Sign-in is disabled" in page.text and 'name="key"' not in page.text
    assert c.post("/login", data={"key": "", "csrf": token}).status_code == 503
    assert c.get("/new").status_code == 303


def test_key_comparison_is_constant_time() -> None:
    assert "compare_digest" in (WEB / "security.py").read_text(encoding="utf-8")
    assert security.check_key(TEST_API_KEY) and not security.check_key(TEST_API_KEY[:-1])


# ---- CSRF and cross-site requests -------------------------------------------------------------


def _suppressed(tracked_id: int) -> bool:
    with session_scope() as s:
        return s.get(TrackedFinding, tracked_id).status.value == "SUPPRESSED"


def test_a_post_without_this_sessions_token_changes_nothing(project: Path) -> None:
    c = signed_in()
    url = "/p/1/findings/1/suppress"
    assert c.post(url, data={"reason": "not a real issue"}).status_code == 403
    assert c.post(url, data={"reason": "not a real issue", "csrf": "forged"}).status_code == 403
    other = signed_in()                                        # another session's valid token
    assert c.post(url, data={"reason": "not a real issue", "csrf": csrf(other, "/new")}).status_code == 403
    assert not _suppressed(1)
    assert post(c, url, {"reason": "not a real issue"}).status_code == 200 and _suppressed(1)


@pytest.mark.parametrize("headers", [{"Origin": "https://attacker.example"}, {"Origin": "null"},
                                     {"Origin": "http://127.0.0.1:9999"}, {"Sec-Fetch-Site": "cross-site"},
                                     {"Sec-Fetch-Site": "same-site"}])
def test_a_cross_site_post_is_refused_even_with_a_valid_token(project: Path, headers: dict) -> None:
    c = signed_in()
    token = csrf(c, "/new")
    response = c.post("/p/1/findings/1/suppress", data={"reason": "not a real issue", "csrf": token}, headers=headers)
    assert response.status_code == 403 and not _suppressed(1)


def test_a_same_origin_browser_post_is_accepted(project: Path) -> None:
    c = signed_in()
    headers = {"Origin": "http://127.0.0.1:8080", "Sec-Fetch-Site": "same-origin", **HTMX}
    response = c.post("/p/1/findings/1/suppress", data={"reason": "not a real issue", "csrf": csrf(c, "/new")},
                      headers=headers)
    assert response.status_code == 200 and _suppressed(1)


# ---- no lab mode --------------------------------------------------------------------------------


def test_there_is_no_route_that_runs_code(project: Path) -> None:
    app = create_web_app()
    paths = [getattr(r, "path", "") for r in app.routes]
    assert not [p for p in paths if "lab" in p.lower()]
    c = signed_in(app)
    assert post(c, "/p/1/verify", {"finding": "1", "how": "lab"}).status_code == 400


# ---- scanned content is text, never markup ------------------------------------------------------


def _payload_scanners() -> list[PatternScanner]:
    return [PatternScanner("bandit", {f"B666 {PAYLOAD}": (r"os\.system\(", "CWE-78", "HIGH")})]


def test_scanned_content_is_escaped_on_every_page(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pipeline, "all_scanners", _payload_scanners)
    code = tmp_path / "code"
    code.mkdir()
    (code / EVIL_FILE).write_text(f'"""{PAYLOAD}"""\nimport os\n\n\ndef handler(name):\n'
                                  f'    os.system("echo " + name)  # {PAYLOAD}\n', encoding="utf-8")
    actions.scan_checkout("evil", str(code), label=PAYLOAD[:120])     # project names are allowlisted; labels are free text
    c = signed_in()
    shown = [c.get(url) for url in _pages()]
    shown.append(post(c, "/p/1/prompt", {"finding": "1", "strategy": "S0", "path": str(code)}))   # S0 quotes the message
    shown.append(post(c, "/p/1/lint", {"finding": "1", "text": PAYLOAD, "bound": "true", "fix": "true",
                                       "path": str(code)}))
    (code / EVIL_FILE).write_text("import os\n\n\ndef handler(name):\n    return name\n", encoding="utf-8")
    shown.append(post(c, "/p/1/verify", {"finding": "1", "how": "rescan", "path": str(code)}))
    shown.append(c.get("/p/1/verify"))

    for response in shown:
        assert response.status_code == 200, (response.request.url, response.text[:300])
        html = response.text
        assert "<img src=x" not in html and "<script>alert" not in html, response.request.url
        assert "x'onmouseover" not in html, response.request.url
        assert not re.search(r'(href|src|action|hx-[a-z]+)="[^"]*attacker', html), response.request.url
    everything = "\n".join(r.text for r in shown)
    # Positive control: the payload IS displayed -- escaped, as text -- so the checks above are not vacuous.
    assert "&lt;img src=x onerror=alert(1)&gt;" in everything and "&lt;script&gt;alert(2)&lt;/script&gt;" in everything
    assert "x&#39;onmouseover=alert(3).py" in everything
    assert "VERIFIED_RESOLVED" in shown[-2].text


# ---- static guarantees ---------------------------------------------------------------------------


def test_nothing_is_ever_marked_safe() -> None:
    assert render.env.autoescape is True
    for path in (WEB / "templates").glob("*.html"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\|\s*safe\b", text), path.name
        assert "autoescape false" not in text.lower() and "markup" not in text.lower(), path.name
    for path in WEB.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            assert not (isinstance(node, ast.Name) and node.id == "Markup"), path.name
            assert not (isinstance(node, ast.Attribute) and node.attr == "Markup"), path.name
            assert not (isinstance(node, ast.ImportFrom) and node.module == "markupsafe"), path.name
            if isinstance(node, ast.keyword) and node.arg == "autoescape":
                assert isinstance(node.value, ast.Constant) and node.value.value is True, path.name


def test_templates_have_no_inline_script_style_or_handlers() -> None:
    for path in (WEB / "templates").glob("*.html"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), path.name
        assert "<style" not in text and not re.search(r"\sstyle=", text), path.name
        assert not re.search(r"\son[a-z]+=", text) and "hx-on" not in text and "javascript:" not in text, path.name


def test_the_vendored_htmx_is_the_pinned_release() -> None:
    assert hashlib.sha256(HTMX_FILE.read_bytes()).hexdigest() == HTMX_SHA256
    head = (WEB / "templates" / "_head.html").read_text(encoding="utf-8")
    assert f'src="/static/{HTMX_FILE.name}"' in head


def test_htmx_is_configured_without_eval_or_cross_origin_requests() -> None:
    head = (WEB / "templates" / "_head.html").read_text(encoding="utf-8")
    config = json.loads(re.search(r'name="htmx-config" content=\'([^\']+)\'', head).group(1))
    assert config["allowEval"] is False and config["allowScriptTags"] is False
    assert config["selfRequestsOnly"] is True and config["includeIndicatorStyles"] is False
    assert config["historyCacheSize"] == 0
