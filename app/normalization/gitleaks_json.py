"""Gitleaks JSON report -> NormalizedFinding.

Gitleaks is run *without* ``--redact`` into a report inside the scan's scratch
directory -- the same directory that already holds the cloned secret, deleted
with it. That lets us mask the exact secret value out of the source line, which
gives a snippet that keeps the variable name (so the fingerprint is meaningful)
but never contains the secret. The raw ``Secret``/``Match`` fields are read here
and discarded; they never reach the database, the logs, or the LLM.

Gitleaks' own ``Fingerprint`` field embeds the line number
(``config.py:stripe-access-token:10``), so it is deliberately ignored.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.core.paths import repo_relative, safe_join
from app.core.redaction import mask_secret, redact
from app.normalization.finding import MalformedOutputError, NormalizedFinding

_MAX_SOURCE_BYTES = 2 * 1024 * 1024


def _source_line(root: Path, rel_path: str, line_no: int | None) -> str:
    if not line_no or line_no < 1:
        return ""
    try:
        target = safe_join(root, rel_path)
        if target.stat().st_size > _MAX_SOURCE_BYTES:
            return ""
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[line_no - 1] if line_no <= len(lines) else ""
    except (OSError, ValueError):
        return ""


def parse_gitleaks(text: str, root: Path) -> tuple[list[NormalizedFinding], int]:
    """Return (findings, dropped_out_of_root)."""
    try:
        payload = json.loads(text) if text.strip() else []
    except json.JSONDecodeError as exc:
        raise MalformedOutputError(f"gitleaks report is not valid JSON: {exc}") from exc
    if payload is None:
        payload = []
    if not isinstance(payload, list):
        raise MalformedOutputError("gitleaks report is not a JSON array")

    findings: list[NormalizedFinding] = []
    dropped = 0
    for item in payload:
        if not isinstance(item, dict) or not isinstance(item.get("RuleID"), str):
            raise MalformedOutputError("gitleaks entry without RuleID")
        rel = repo_relative(str(item.get("File", "")), root)
        if not rel:
            dropped += 1
            continue
        line = item.get("StartLine") if isinstance(item.get("StartLine"), int) else None
        secret = item.get("Secret") if isinstance(item.get("Secret"), str) else None
        snippet = mask_secret(_source_line(root, rel, line), secret).strip()
        description = redact(str(item.get("Description", "") or "Hard-coded secret detected"))
        findings.append(
            NormalizedFinding(
                tool="gitleaks",
                rule_id=item["RuleID"],
                message=description,
                file_path=rel,
                start_line=line,
                end_line=item.get("EndLine") if isinstance(item.get("EndLine"), int) else line,
                severity="HIGH",
                snippet=snippet,
            )
        )
        # Drop the only references to the raw secret as early as possible.
        item.pop("Secret", None)
        item.pop("Match", None)
    return findings, dropped
