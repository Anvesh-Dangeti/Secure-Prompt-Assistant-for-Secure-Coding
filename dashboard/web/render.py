"""Server-side rendering: one Jinja2 environment with autoescaping forced on.

Everything from a scanned repository -- code, file names, rule ids, scanner
messages, gate details, scan labels -- reaches the page only through
``{{ ... }}``, which HTML-escapes it, quotes included, so it is safe inside
attribute values too. Nothing is ever marked safe: there is no ``|safe`` filter
and no ``Markup`` anywhere (a test asserts it), so scanned text has no path to
becoming markup. Scanned values are never placed in URLs, ``hx-*`` attributes
or scripts; links carry only our own integer ids.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from starlette.templating import Jinja2Templates

from dashboard import data
from dashboard.web.security import csrf_token

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _when(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M") if value else "-"


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.0%}"


env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True, undefined=StrictUndefined,
                  trim_blocks=True, lstrip_blocks=True)
env.filters["when"] = _when
env.filters["pct"] = _pct
templates = Jinja2Templates(env=env)


def is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def page(request: Request, name: str, *, project: data.ProjectRow | None = None, tab: str | None = None,
         status_code: int = 200, **context: object) -> HTMLResponse:
    """A full page: the shell (project switcher, navigation, one-time notice) around ``name``."""
    context.update(project=project, tab=tab, projects=data.projects(), csrf=csrf_token(request),
                   notice=request.session.pop("notice", None))
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def partial(request: Request, name: str, *, status_code: int = 200, **context: object) -> HTMLResponse:
    """A fragment swapped into a page by htmx (or shown alone without JavaScript)."""
    context.setdefault("csrf", csrf_token(request))
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def problem(request: Request, title: str, detail: object, status_code: int = 422) -> HTMLResponse:
    """A refused or failed action: our own headline, plus the (escaped) reason the action gave."""
    return partial(request, "_problem.html", status_code=status_code, title=title, detail=str(detail))


def notice(request: Request, text: str) -> None:
    """A one-line message for the next full page (stored in the signed session cookie)."""
    request.session["notice"] = text


def go(request: Request, url: str) -> Response:
    """After a successful action: htmx follows HX-Redirect; a plain form follows the 303."""
    if is_htmx(request):
        return Response(status_code=200, headers={"HX-Redirect": url})
    return RedirectResponse(url, status_code=303)
