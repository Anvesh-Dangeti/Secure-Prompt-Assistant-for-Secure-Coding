"""The web interface's FastAPI application: middleware, error pages and routes.

It is a separate application from the HTTP API (``app/main.py``): the API
authenticates each call with an ``X-API-Key`` header and serves JSON; this one
serves pages to a browser, so it signs a session in once and protects every
form with a CSRF token. Both refuse lab mode, the only path that runs code.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.session import init_db
from dashboard.web import security
from dashboard.web.render import is_htmx, templates
from dashboard.web.routes import auth, findings, history, overview, prompt, verify

log = get_logger(__name__)
STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    configure_logging(get_settings().log_level)
    init_db()
    if not security.key_configured():
        log.warning("SPA_API_KEY is not set: the web interface will refuse every sign-in")
    yield


def _error(request: Request, status: int, title: str) -> Response:
    # No session access: this also renders for crashes caught outside the session middleware.
    return templates.TemplateResponse(request, "error.html", {"title": title}, status_code=status)


def create_web_app() -> FastAPI:
    # No OpenAPI schema or docs pages: this application serves a browser, not clients.
    app = FastAPI(title="Secure Prompt Assistant", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.throttle = security.LoginThrottle()
    app.add_middleware(SessionMiddleware, secret_key=secrets.token_urlsafe(32), session_cookie=security.SESSION_COOKIE,
                       max_age=security.SESSION_MAX_AGE_S, same_site="strict", https_only=False)

    @app.middleware("http")
    async def guard(request: Request, call_next):  # noqa: ANN001, ANN202
        # Outermost: refused requests never reach a route, and every response -- pages, static
        # files, errors and refusals alike -- carries the same security headers.
        refused = security.refusal(request)
        if refused:
            response: Response = PlainTextResponse(refused[1], status_code=refused[0])
        else:
            try:
                response = await call_next(request)
            except Exception:
                # Logged server-side (through the redacting logger); the page never shows a traceback or a path.
                log.exception("unhandled error", extra={"path": request.url.path})
                response = _error(request, 500, "Something went wrong. The details are in the server log.")
        for name, value in security.HEADERS.items():
            response.headers[name] = value
        return response

    @app.exception_handler(security.NotSignedIn)
    async def not_signed_in(request: Request, _exc: Exception) -> Response:
        if is_htmx(request):
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(security.CsrfRejected)
    async def csrf_rejected(request: Request, _exc: Exception) -> Response:
        return _error(request, 403, "This form expired or did not come from this page. Reload and try again.")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        titles = {404: "Not found.", 405: "Method not allowed."}
        return _error(request, exc.status_code, titles.get(exc.status_code, "Request refused."))

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, _exc: Exception) -> Response:
        # The validation detail echoes input back; the page says only that the request was invalid.
        return _error(request, 400, "Invalid request.")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    for module in (auth, overview, findings, prompt, verify, history):
        app.include_router(module.router)
    return app
