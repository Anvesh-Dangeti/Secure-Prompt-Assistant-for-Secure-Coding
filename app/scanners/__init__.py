"""Scanner adapters. ``all_scanners()`` is the live-loop set (docs/scope_decisions.md)."""

from __future__ import annotations

from app.scanners.bandit import BanditScanner
from app.scanners.base import Scanner, ScannerResult
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.pip_audit import PipAuditScanner
from app.scanners.semgrep import SemgrepScanner


def all_scanners() -> list[Scanner]:
    return [SemgrepScanner(), BanditScanner(), GitleaksScanner(), PipAuditScanner()]


__all__ = ["Scanner", "ScannerResult", "all_scanners"]
