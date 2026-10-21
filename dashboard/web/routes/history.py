"""Scan and commit history: every scan of the project, what it changed, and what each scanner could see."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from dashboard import data
from dashboard.web import svg
from dashboard.web.render import is_htmx, page, partial
from dashboard.web.routes.common import project_or_404
from dashboard.web.routes.overview import scan_points
from dashboard.web.security import require_session

router = APIRouter(dependencies=[Depends(require_session)])


@router.get("/p/{project_id}/history")
def history(request: Request, project_id: int, scan: int | None = None) -> Response:
    project = project_or_404(project_id)
    scans = data.scan_history(project_id)
    ids = [s.id for s in scans]
    chosen = scan if scan in ids else (ids[-1] if ids else None)
    runs = data.scanner_runs(chosen) if chosen is not None else []
    if is_htmx(request):
        return partial(request, "_scanner_runs.html", runs=runs, chosen=chosen)
    return page(request, "history.html", project=project, tab="history", scans=scans, chosen=chosen, runs=runs,
                chart=svg.line(scan_points(scans)), transitions=data.TRANSITIONS)
