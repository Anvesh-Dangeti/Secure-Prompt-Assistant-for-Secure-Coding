"""Findings: filter the tracked findings; inspect one -- evidence, lifecycle, verdicts -- and suppress or restore it."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import Response

from app.normalization.finding import SEVERITIES
from dashboard import actions, data
from dashboard.actions import MIN_REASON, ActionError
from dashboard.web.render import go, is_htmx, notice, page, partial, problem
from dashboard.web.routes.common import OPEN, finding_or_404, project_or_404
from dashboard.web.security import require_csrf, require_session

router = APIRouter(dependencies=[Depends(require_session)])


@router.get("/p/{project_id}/findings")
def findings(request: Request, project_id: int, state: list[str] = Query(default=[]),
             severity: list[str] = Query(default=[]), tool: list[str] = Query(default=[]),
             filtered: bool = False) -> Response:
    project = project_or_404(project_id)
    everything = data.tracked(project_id)
    tools = sorted({r.tool for r in everything})
    # Filter values are matched against allowlists; anything else is ignored, never echoed or queried.
    states = [s for s in state if s in data.STATES] if filtered else list(OPEN)
    severities = [s for s in severity if s in SEVERITIES]
    chosen_tools = [t for t in tool if t in tools]
    rows = data.tracked(project_id, states or None, severities or None, chosen_tools or None)
    context = {"project": project, "rows": rows, "total": len(everything)}
    if is_htmx(request):
        return partial(request, "_findings_table.html", **context)
    return page(request, "findings.html", tab="findings", states=states, severities=severities, tools=tools,
                chosen_tools=chosen_tools, all_states=data.STATES, all_severities=SEVERITIES, **context)


@router.get("/p/{project_id}/findings/{tracked_id}")
def finding(request: Request, project_id: int, tracked_id: int) -> Response:
    project = project_or_404(project_id)
    finding_or_404(project_id, tracked_id)
    detail = data.finding_detail(tracked_id)
    if detail is None:
        raise HTTPException(status_code=404)
    return page(request, "finding.html", project=project, tab="findings", d=detail, min_reason=MIN_REASON)


@router.post("/p/{project_id}/findings/{tracked_id}/suppress", dependencies=[Depends(require_csrf)])
def suppress(request: Request, project_id: int, tracked_id: int,
             reason: str = Form("", max_length=500)) -> Response:
    finding_or_404(project_id, tracked_id)
    try:
        actions.suppress_finding(tracked_id, reason)
    except ActionError as exc:
        return problem(request, "Not suppressed.", exc)
    notice(request, f"Finding #{tracked_id} suppressed as a false positive. It stays on record.")
    return go(request, f"/p/{project_id}/findings/{tracked_id}")


@router.post("/p/{project_id}/findings/{tracked_id}/unsuppress", dependencies=[Depends(require_csrf)])
def unsuppress(request: Request, project_id: int, tracked_id: int) -> Response:
    finding_or_404(project_id, tracked_id)
    try:
        actions.unsuppress_finding(tracked_id)
    except ActionError as exc:
        return problem(request, "Could not withdraw the suppression.", exc)
    notice(request, f"Suppression of finding #{tracked_id} withdrawn.")
    return go(request, f"/p/{project_id}/findings/{tracked_id}")
