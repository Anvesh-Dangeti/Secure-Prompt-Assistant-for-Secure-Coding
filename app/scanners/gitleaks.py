"""Gitleaks adapter (secrets).

Scans the working tree only (``dir`` mode). Clones are shallow (``--depth=1``),
so there is no history to scan; secrets that exist only in older commits are
out of scope and documented as such.

``--ignore-gitleaks-allow`` because ``gitleaks:allow`` comments are controlled
by the code under scan. In-repo ``.gitleaks.toml`` / ``.gitleaksignore`` files
are removed from the scratch copy by the pipeline before any scanner runs.
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import get_settings
from app.core.subprocess_runner import read_capped_file, run_tool
from app.db.models import ToolStatus
from app.normalization.gitleaks_json import parse_gitleaks
from app.scanners.base import RunOutcome, Scanner, outcome_from_process


class GitleaksScanner(Scanner):
    name = "gitleaks"
    binary = "gitleaks"
    tool_dir = "gitleaks"
    version_args = ("version",)

    def _run(self, exe: Path, root: Path, out_dir: Path) -> RunOutcome:
        settings = get_settings()
        report = out_dir / "gitleaks.json"
        args = [
            str(exe), "dir", ".", "--report-format", "json", "--report-path", str(report),
            "--no-banner", "--no-color", "--log-level", "error", "--exit-code", "0",
            "--ignore-gitleaks-allow", "--max-target-megabytes", "5",
        ]
        proc = run_tool(args, cwd=root, timeout=settings.scanner_timeout_seconds)
        failure = outcome_from_process(proc.timed_out, proc.returncode, {0}, proc.stderr, self.name)
        if failure:
            return failure
        if not report.is_file():
            return RunOutcome([], ToolStatus.ERROR, error="gitleaks produced no report")
        try:
            findings, dropped = parse_gitleaks(read_capped_file(report), root)
        finally:
            # The unredacted report must not outlive parsing, even on error.
            report.unlink(missing_ok=True)
        notes = [f"{dropped} result(s) outside the scan root were discarded"] if dropped else []
        return RunOutcome(findings, notes=notes)
