"""Bandit adapter (SAST, second independent engine).

Paper 3 used Bandit as its primary detector (Cohen's kappa = 0.87 against
manual review); running it alongside Semgrep gives an inter-tool agreement
measurement instead of a single engine's opinion.

``--ignore-nosec`` for the same reason Semgrep runs with ``--disable-nosem``:
a ``# nosec`` comment is not a fix.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.config import get_settings
from app.core.redaction import redact
from app.core.subprocess_runner import read_capped_file, run_tool
from app.db.models import ToolStatus
from app.normalization.finding import NormalizedFinding, normalise_severity
from app.normalization.sarif import cwe_from_tags, parse_sarif
from app.scanners.base import EXCLUDED_DIRS, RunOutcome, Scanner, outcome_from_process

_BANDIT_DEFAULT_EXCLUDES = (".svn", "CVS", ".bzr", ".hg", ".git", "__pycache__", ".tox", ".eggs", "*.egg")


def strip_line_numbers(code: str) -> str:
    """Remove ``"22 import os"``-style prefixes Bandit's JSON output embeds.

    Bandit's SARIF snippet is clean in 1.9.4, but its JSON ``code`` field is
    not. Line numbers leaking into a fingerprint make every finding below an
    inserted line look RESOLVED-then-NEW (caught in Phase 0 by
    tests/unit/test_fingerprint_stability.py), so this stays as a guard.
    """
    return "\n".join(re.sub(r"^\s*\d+\s", "", line) for line in code.splitlines())


class BanditScanner(Scanner):
    name = "bandit"
    binary = "bandit"
    tool_dir = "bandit"

    def _run(self, exe: Path, root: Path, out_dir: Path) -> RunOutcome:
        settings = get_settings()
        report = out_dir / "bandit.sarif"
        excludes = ",".join(dict.fromkeys((*_BANDIT_DEFAULT_EXCLUDES, *EXCLUDED_DIRS)))
        args = [str(exe), "-r", ".", "-f", "sarif", "-o", str(report), "-q", "--ignore-nosec", "-x", excludes]

        proc = run_tool(args, cwd=root, timeout=settings.scanner_timeout_seconds)
        # Bandit: 0 = no issues, 1 = issues found. Anything else is a failure.
        failure = outcome_from_process(proc.timed_out, proc.returncode, {0, 1}, proc.stderr, self.name)
        if failure:
            return failure
        if not report.is_file():
            return RunOutcome([], ToolStatus.ERROR, error="bandit produced no report")

        run = parse_sarif(read_capped_file(report), root)
        findings = []
        for r in run.results:
            props = r.properties
            severity = normalise_severity(str(props.get("issue_severity") or r.level or ""))
            findings.append(
                NormalizedFinding(
                    tool=self.name,
                    rule_id=r.rule_id,
                    message=redact(r.message),
                    file_path=r.file_path,
                    start_line=r.start_line,
                    end_line=r.end_line,
                    severity=severity,
                    snippet=redact(strip_line_numbers(r.snippet)),
                    cwe_reported=cwe_from_tags(r.rule_tags),
                )
            )
        notes = [f"{run.dropped_out_of_root} result(s) outside the scan root were discarded"] \
            if run.dropped_out_of_root else []
        outcome = RunOutcome(findings, notes=notes, unverified_scopes={f"file:{p}" for p in run.error_files})
        if not run.execution_successful:
            outcome.status = ToolStatus.ERROR
            outcome.error = "bandit reported an unsuccessful execution"
        return outcome
