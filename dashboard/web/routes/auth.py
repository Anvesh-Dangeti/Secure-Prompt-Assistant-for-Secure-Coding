"""Sign in with SPA_API_KEY, and sign out."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response

from dashboard.web import security
from dashboard.web.render import partial

router = APIRouter()


def _form(request: Request, status_code: int = 200, error: str | None = None) -> Response:
    state = ("disabled" if not security.key_configured() else
             "locked" if request.app.state.throttle.locked() else "open")
    return partial(request, "login.html", status_code=status_code, state=state, error=error)


@router.get("/login")
def login_form(request: Request) -> Response:
    if security.signed_in(request):
        return RedirectResponse("/", status_code=303)
    return _form(request)


@router.post("/login", dependencies=[Depends(security.require_csrf)])
async def login(request: Request, key: str = Form("", max_length=512)) -> Response:
    throttle = request.app.state.throttle
    if not security.key_configured():
        return _form(request, 503)
    if throttle.locked():
        return _form(request, 429)
    if security.check_key(key):
        throttle.succeeded()
        security.sign_in(request)
        return RedirectResponse("/", status_code=303)
    throttle.failed()
    await asyncio.sleep(security.FAILURE_DELAY_S)
    return _form(request, 401, error="Wrong key.")


@router.post("/logout", dependencies=[Depends(security.require_csrf)])
def logout(request: Request) -> Response:
    security.sign_out(request)
    return RedirectResponse("/login", status_code=303)
