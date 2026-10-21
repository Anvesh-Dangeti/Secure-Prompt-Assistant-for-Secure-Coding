"""Overview: what is open, how severe, how it has moved, what the last scan could see -- and scanning."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from dashboard import actions, data
from dashboard.actions import ActionError
from dashboard.web import svg
from dashboard.web.render import go, notice, page, problem
from dashboard.web.routes.common import checkout, project_or_404, remember_checkout
from dashboard.web.security import require_csrf, require_session

router = APIRouter(dependencies=[Depends(require_session)])
OPEN_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def scan_points(scans: list[data.ScanRow]) -> list[tuple[str, int, str]]:
    return [(f"#{s.id}", s.findings, f"Scan #{s.id} ({s.label or 'no label'}, {s.status}): {s.findings} findings")
            for s in scans]


@router.get("/")
def home(request: Request) -> Response:
    projects = data.projects()
    if projects:
        return RedirectResponse(f"/p/{projects[0].id}", status_code=303)
    return page(request, "start.html", checkout=checkout(request))


@router.get("/new")
def new_scan(request: Request) -> Response:
    return page(request, "start.html", checkout=checkout(request))


@router.get("/open")
def open_project(project: int) -> Response:
    project_or_404(project)
    return RedirectResponse(f"/p/{project}", status_code=303)


@router.get("/p/{project_id}")
def overview(request: Request, project_id: int) -> Response:
    o = data.overview(project_id)
    if o is None:
        raise HTTPException(status_code=404)
    scans = data.scan_history(project_id)
    return page(request, "overview.html", project=o.project, tab="overview", o=o, severities=OPEN_SEVERITIES,
                owasp_chart=svg.hbars(o.open_by_owasp), scan_chart=svg.line(scan_points(scans)),
                checkout=checkout(request))


def _done(request: Request, summary) -> Response:  # noqa: ANN001
    notice(request, f"Scan #{summary.scan_id} finished: {summary.status}, {summary.findings} findings.")
    return go(request, f"/p/{summary.project_id}")


@router.post("/scan", dependencies=[Depends(require_csrf)])
def scan_new(request: Request, name: str = Form("", max_length=200), path: str = Form("", max_length=4096),
             label: str = Form("", max_length=120)) -> Response:
    try:
        summary = actions.scan_checkout(name, path, label or None)
    except ActionError as exc:
        return problem(request, "The scan did not run.", exc)
    remember_checkout(request, path)
    return _done(request, summary)


@router.post("/p/{project_id}/scan", dependencies=[Depends(require_csrf)])
def rescan(request: Request, project_id: int, path: str = Form("", max_length=4096),
           label: str = Form("", max_length=120)) -> Response:
    project = project_or_404(project_id)
    try:
        summary = actions.rescan(project.id, path or None, label or None)
    except ActionError as exc:
        return problem(request, "The scan did not run.", exc)
    if path:
        remember_checkout(request, path)
    return _done(request, summary)
