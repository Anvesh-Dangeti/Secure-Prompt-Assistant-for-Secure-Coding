"""Verify: rescan the fixed code and let the gates decide -- never the model, never this page.

Developer mode only (gates 1, 2, 3a). Nothing here executes the scanned code;
lab mode, which does, is a CLI instrument and has no route.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

from dashboard import actions, data
from dashboard.actions import ActionError
from dashboard.web.render import page, partial, problem
from dashboard.web.routes.common import checkout, finding_or_404, pick, project_or_404, remember_checkout
from dashboard.web.security import require_csrf, require_session

router = APIRouter(dependencies=[Depends(require_session)])


@router.get("/p/{project_id}/verify")
def verify_page(request: Request, project_id: int, finding: int | None = None) -> Response:
    project = project_or_404(project_id)
    rows = data.tracked(project_id)
    selected = pick(rows, finding)
    return page(request, "verify.html", project=project, tab="verify", rows=rows, selected=selected,
                history=data.verifications(selected.id) if selected else [], checkout=checkout(request))


@router.post("/p/{project_id}/verify", dependencies=[Depends(require_csrf)])
def verify(request: Request, project_id: int, finding: int = Form(...),
           how: Literal["rescan", "latest"] = Form("rescan"), path: str = Form("", max_length=4096)) -> Response:
    project = project_or_404(project_id)
    finding_or_404(project_id, finding)
    try:
        if how == "rescan":
            summary, result = actions.rescan_and_verify(finding, path if project.source_type == "zip" else None)
            message = f"Scan #{summary.scan_id} ({summary.status}) → verdict {result.verdict}"
        else:
            result = actions.verify_against(finding)
            message = f"Latest scan judged → verdict {result.verdict}"
    except ActionError as exc:
        return problem(request, "Not verified.", exc)
    if how == "rescan" and project.source_type == "zip":
        remember_checkout(request, path)
    return partial(request, "_verify_result.html", message=message, verdict=result.verdict,
                   history=data.verifications(finding))
