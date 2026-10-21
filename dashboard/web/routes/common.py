"""Lookups shared by the page routers: a project and a finding that belongs to it, or 404."""

from __future__ import annotations

from fastapi import HTTPException, Request

from dashboard import data

OPEN = ["NEW", "STILL_OPEN", "REGRESSION"]
CHECKOUT = "checkout"       # session key: the developer's checkout path, remembered across pages


def project_or_404(project_id: int) -> data.ProjectRow:
    project = data.project(project_id)
    if project is None:
        raise HTTPException(status_code=404)
    return project


def finding_or_404(project_id: int, tracked_id: int) -> data.TrackedRow:
    """A finding is addressed through its project, so a URL can never mix one project's page with another's finding."""
    row = next((r for r in data.tracked(project_id) if r.id == tracked_id), None)
    if row is None:
        raise HTTPException(status_code=404)
    return row


def pick(rows: list[data.TrackedRow], wanted: int | None) -> data.TrackedRow | None:
    return next((r for r in rows if r.id == wanted), rows[0] if rows else None)


def remember_checkout(request: Request, path: str) -> None:
    # Only after an action accepted it (actions.checkout_path validated it); the cookie is signed, HttpOnly.
    request.session[CHECKOUT] = path.strip()


def checkout(request: Request) -> str:
    return str(request.session.get(CHECKOUT, ""))
