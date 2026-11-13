"""Remediation prompts over HTTP, for a developer whose code is not on the server.

Scans keep evidence, not source code, so a prompt needs the flagged code again.
On one machine the dashboard reads it from the developer's checkout; on a shared
server the ``spa`` connector sends it. Data minimisation decides what it sends:

* **one file** -- the file the finding is in, never the repository;
* the path must be **exactly the finding's own path**, so a caller cannot use
  this route to write anything else into scratch space;
* at most ``SPA_MAX_CONTEXT_FILE_BYTES``, the same limit the context reader has;
* written into a private scratch directory that is deleted when the request
  ends -- nothing is stored.

The prompt is then built exactly as the CLI and the dashboard build it, and the
same context window (about ten lines either side) is all that goes into it.
"""

from __future__ import annotations

from pathlib import PurePosixPath

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.ai.context import ContextError
from app.ai.prompt_builder import PromptRejected
from app.ai.service import FindingNotFound, context_for_tracked, finding_for_tracked, prompt_for_context
from app.ai.strategies import get_strategy
from app.api.deps import Principal, current_principal, get_db
from app.api.findings import tracked_or_404
from app.api.schemas import PromptOut, PromptRequest
from app.core.config import get_settings
from app.core.paths import PathTraversalError, safe_join
from app.core.scratch import scratch_dir

router = APIRouter(prefix="/api/v1", tags=["prompts"], dependencies=[Depends(current_principal)])


@router.post("/tracked/{tracked_id}/prompt", response_model=PromptOut)
def prompt_for_tracked(tracked_id: int, body: PromptRequest, db: Session = Depends(get_db),
                       principal: Principal = Depends(current_principal)) -> PromptOut:
    tracked_or_404(db, tracked_id, principal)
    try:
        strategy = get_strategy(body.strategy).id
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if len(body.content.encode("utf-8")) > get_settings().max_context_file_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "file too large to build a prompt from")
    try:
        expected = finding_for_tracked(db, tracked_id).file_path
    except FindingNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    # The server already knows which file it needs; anything else is refused, not interpreted.
    if body.file_path != expected:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"send the finding's own file: {expected}")

    with scratch_dir("prompt-") as work:
        try:
            target = safe_join(work, *PurePosixPath(expected).parts)
        except PathTraversalError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid file path") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body.content.encode("utf-8"))   # bytes: line endings arrive unchanged
        try:
            result = prompt_for_context(context_for_tracked(db, tracked_id, work), strategy)
        except (ContextError, PromptRejected) as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return PromptOut(tracked_finding_id=tracked_id, file_path=expected, strategy=result.strategy,
                     prompt=result.rendered, tokens=result.tokens, lint=result.lint,
                     explanation_source=result.explanation_source, warning=result.warning)
