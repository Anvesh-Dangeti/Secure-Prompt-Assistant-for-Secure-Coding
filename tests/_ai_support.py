"""Recorded scanner findings for the AI-layer tests.

``tests/data/flask_vuln_app_findings.json`` holds the 24 in-scope findings the
four real scanners reported on ``fixtures/flask_vuln_app`` (8 Oct pins), so
the AI layer is tested against real scanner output without needing the
scanners installed.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.ai.context import FindingContext, extract_context
from app.normalization.finding import NormalizedFinding

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "flask_vuln_app"
RECORDED = ROOT / "tests" / "data" / "flask_vuln_app_findings.json"
NONCE = "0123456789abcdef"


def recorded_findings() -> list[NormalizedFinding]:
    return [NormalizedFinding(**raw) for raw in json.loads(RECORDED.read_text(encoding="utf-8"))]


def finding(rule_suffix: str) -> NormalizedFinding:
    """The first recorded finding whose rule id ends with ``rule_suffix`` (e.g. "B608")."""
    return next(f for f in recorded_findings() if f.rule_id.endswith(rule_suffix))


def context(rule_suffix: str, root: Path = FIXTURE) -> FindingContext:
    return extract_context(finding(rule_suffix), root)


def all_contexts() -> list[FindingContext]:
    return [extract_context(f, FIXTURE) for f in recorded_findings()]
