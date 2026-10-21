"""Prompt & lint: build the remediation prompt for the developer's own assistant, then lint whatever they edit.

No model runs here and no tokens are spent: the explanation comes from the
template provider, exactly as in the CLI's ``prompt`` and ``lint-prompt``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import Response

from app.ai.linter import RULES
from app.ai.strategies import DEFAULT_STRATEGY, STRATEGIES
from app.cli_ai import MAX_PROMPT_INPUT
from dashboard import actions, data
from dashboard.actions import ActionError
from dashboard.web.render import page, partial, problem
from dashboard.web.routes.common import OPEN, checkout, finding_or_404, pick, project_or_404, remember_checkout
from dashboard.web.security import require_csrf, require_session

router = APIRouter(dependencies=[Depends(require_session)])


@router.get("/p/{project_id}/prompt")
def prompt_page(request: Request, project_id: int, finding: int | None = None) -> Response:
    project = project_or_404(project_id)
    rows = data.tracked(project_id, states=OPEN)
    return page(request, "prompt.html", project=project, tab="prompt", rows=rows, selected=pick(rows, finding),
                strategies=STRATEGIES, default_strategy=DEFAULT_STRATEGY, checkout=checkout(request),
                max_prompt=MAX_PROMPT_INPUT)


@router.post("/p/{project_id}/prompt", dependencies=[Depends(require_csrf)])
def build(request: Request, project_id: int, finding: int = Form(...),
          strategy: str = Form(DEFAULT_STRATEGY, max_length=8), path: str = Form("", max_length=4096)) -> Response:
    finding_or_404(project_id, finding)
    try:
        view = actions.prompt_for(finding, path, strategy)
    except ActionError as exc:
        return problem(request, "No prompt was built.", exc)
    remember_checkout(request, path)
    return partial(request, "_prompt_result.html", view=view, strategy_name=STRATEGIES[view.strategy].name,
                   rules=RULES)


@router.post("/p/{project_id}/lint", dependencies=[Depends(require_csrf)])
def lint(request: Request, project_id: int, text: str = Form("", max_length=MAX_PROMPT_INPUT),
         finding: int | None = Form(None), path: str = Form("", max_length=4096), bound: bool = Form(False),
         fix: bool = Form(False)) -> Response:
    if bound and finding is None:
        return problem(request, "Not linted.", "choose a finding, or lint without binding to one")
    if bound:
        finding_or_404(project_id, finding)
        path = path or checkout(request)    # the checkout the prompt was built from
    try:
        result = actions.lint_text(text, finding if bound else None, path if bound else None, fix=fix)
    except ActionError as exc:
        return problem(request, "Not linted.", exc)
    return partial(request, "_lint_result.html", result=result, rules=RULES)
