"""Drive the web interface in tests: Starlette's TestClient standing in for a browser on this machine."""

from __future__ import annotations

import re

from fastapi import FastAPI
from starlette.testclient import TestClient

from dashboard.web.app import create_web_app
from tests._support import TEST_API_KEY

BASE = "http://127.0.0.1:8080"
HTMX = {"HX-Request": "true"}
_CSRF = re.compile(r'name="csrf" value="([^"]+)"')


def client(app: FastAPI | None = None, peer: str = "127.0.0.1") -> TestClient:
    return TestClient(app or create_web_app(), base_url=BASE, client=(peer, 50000), follow_redirects=False)


def csrf(c: TestClient, url: str = "/login") -> str:
    """This session's CSRF token, read from a page the way a browser form carries it."""
    match = _CSRF.search(c.get(url).text)
    assert match, f"no CSRF field on {url}"
    return match.group(1)


def sign_in(c: TestClient, key: str = TEST_API_KEY):  # noqa: ANN201
    return c.post("/login", data={"key": key, "csrf": csrf(c)})


def signed_in(app: FastAPI | None = None) -> TestClient:
    c = client(app)
    response = sign_in(c)
    assert response.status_code == 303 and response.headers["location"] == "/", response.text
    return c


def post(c: TestClient, url: str, data: dict | None = None, *, htmx: bool = True, **kwargs):  # noqa: ANN201
    """A form post from a signed-in page, with that session's CSRF token."""
    return c.post(url, data={"csrf": csrf(c, "/new"), **(data or {})}, headers=HTMX if htmx else None, **kwargs)
