"""The web interface's security envelope: who may connect, who is signed in, and what the browser may do.

* **Loopback only.** The server binds 127.0.0.1 (``__main__``), and every request
  is checked again here: the peer must be a loopback address, and the Host
  header must name loopback. The Host check is what defeats DNS rebinding -- a
  hostile page whose domain resolves to 127.0.0.1 still sends its own name.
* **Signed in with ``SPA_API_KEY``.** Constant-time comparison; closed when no key
  is configured; a one-second delay after each wrong key; and a lockout after
  five failures that is process-wide, because a per-session counter would be
  reset by simply dropping the cookie.
* **Session.** A signed cookie, HttpOnly and SameSite=Strict, whose signing secret
  is random per process start: no secret is stored anywhere, and a restart
  signs everyone out.
* **CSRF.** Every POST carries a per-session token, and requests whose Origin or
  Sec-Fetch-Site headers say they come from another site are refused outright.
* **CSP.** Only same-origin scripts, styles and images; no inline script or
  style, so injected markup could not run even if escaping ever failed; no
  framing; forms post only to this origin.
"""

from __future__ import annotations

import secrets
import threading
import time

from fastapi import Form, Request

from app.cli_ai import MAX_PROMPT_INPUT
from app.core.config import get_settings

LOOPBACK_PEERS = frozenset({"127.0.0.1", "::1"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
SAFE_METHODS = frozenset({"GET", "HEAD"})
ALLOWED_METHODS = SAFE_METHODS | {"POST"}

MAX_FAILURES = 5
LOCKOUT_S = 300.0
FAILURE_DELAY_S = 1.0

# The largest legitimate form is a pasted prompt; anything bigger is refused before it is parsed.
MAX_BODY_BYTES = MAX_PROMPT_INPUT + 64 * 1024
SESSION_COOKIE = "spa_session"
SESSION_MAX_AGE_S = 8 * 3600

CSP = "; ".join((
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "connect-src 'self'",           # htmx requests
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
))
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # Not "no-referrer": under it Chromium sends "Origin: null" on same-origin form posts, which the
    # cross-site check must refuse. "same-origin" keeps a real Origin here and sends nothing elsewhere.
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",            # pages carry code and prompts
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}


# ---- who may connect -------------------------------------------------------------------


def host_name(header: str) -> str:
    """The host part of a Host header: ``127.0.0.1:8080`` -> ``127.0.0.1``, ``[::1]:8080`` -> ``::1``."""
    host = header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end > 0 else ""
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def refusal(request: Request) -> tuple[int, str] | None:
    """(status, message) when the request must be refused before any route sees it; otherwise None."""
    peer = request.client.host if request.client else None
    if peer not in LOOPBACK_PEERS:
        return 403, "This interface only serves this machine."
    if host_name(request.headers.get("host", "")) not in LOOPBACK_HOSTS:
        return 400, "Unexpected Host header."
    if request.method not in ALLOWED_METHODS:
        return 405, "Method not allowed."
    if request.method == "POST":
        if cross_site(request):
            return 403, "Cross-site request refused."
        declared = request.headers.get("content-length")
        if declared is None:
            return 411, "Content-Length required."
        if not declared.isdigit() or int(declared) > MAX_BODY_BYTES:
            return 413, "Request body too large."
    return None


def cross_site(request: Request) -> bool:
    """True when the browser says the request comes from another origin (checked before the CSRF token)."""
    site = request.headers.get("sec-fetch-site")
    if site is not None and site not in {"same-origin", "none"}:
        return True
    origin = request.headers.get("origin")
    return origin is not None and origin != f"{request.url.scheme}://{request.headers.get('host', '')}"


# ---- who is signed in ------------------------------------------------------------------


class NotSignedIn(Exception):
    """The request needs a signed-in session."""


class CsrfRejected(Exception):
    """A state-changing request without this session's CSRF token."""


def key_configured() -> bool:
    key = get_settings().api_key
    return key is not None and bool(key.get_secret_value())


def check_key(entered: str) -> bool:
    key = get_settings().api_key
    if key is None or not key.get_secret_value():
        return False
    # Constant-time: response timing must not reveal how much of the key matched.
    return secrets.compare_digest(entered.encode("utf-8"), key.get_secret_value().encode("utf-8"))


class LoginThrottle:
    """Process-wide: five wrong keys lock the sign-in form for five minutes, whoever sent them."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.failures = 0
        self.locked_until = 0.0

    def locked(self) -> bool:
        with self._lock:
            if self.locked_until and time.monotonic() >= self.locked_until:
                self.failures, self.locked_until = 0, 0.0
            return self.locked_until > 0

    def failed(self) -> None:
        with self._lock:
            self.failures += 1
            if self.failures >= MAX_FAILURES:
                self.locked_until = time.monotonic() + LOCKOUT_S

    def succeeded(self) -> None:
        with self._lock:
            self.failures, self.locked_until = 0, 0.0


def signed_in(request: Request) -> bool:
    return request.session.get("authed") is True


def sign_in(request: Request) -> None:
    # A fresh session: nothing set before sign-in (including its CSRF token) survives it.
    request.session.clear()
    request.session["authed"] = True
    request.session["csrf"] = secrets.token_urlsafe(32)


def sign_out(request: Request) -> None:
    request.session.clear()


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def require_session(request: Request) -> None:
    """Dependency for every page and action except sign-in."""
    if not signed_in(request):
        raise NotSignedIn


def require_csrf(request: Request, csrf: str = Form("")) -> None:
    """Dependency for every POST: the form must carry this session's token."""
    expected = request.session.get("csrf")
    if not expected or not secrets.compare_digest(csrf.encode("utf-8"), str(expected).encode("utf-8")):
        raise CsrfRejected
