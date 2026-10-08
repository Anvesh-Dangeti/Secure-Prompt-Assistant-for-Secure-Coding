"""Semgrep adapter (SAST, primary engine).

Security-relevant flags:
* ``--disable-nosem`` -- ``# nosemgrep`` comments are written by whoever controls
  the code, including an AI "fix". Honouring them would let a fix hide the
  finding instead of removing the weakness, and verification would pass.
* ``--no-git-ignore`` -- an uploaded tree's .gitignore must not hide files.
* ``--metrics=off`` -- no telemetry about the scanned code leaves the machine.
* pinned local ruleset -- reproducible results; its SHA-256 is recorded with
  every run. The live registry is used only as a flagged fallback.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from app.core.config import get_settings
from app.core.redaction import redact
from app.core.subprocess_runner import read_capped_file, run_tool
from app.db.models import ToolStatus
from app.normalization.finding import NormalizedFinding, normalise_severity
from app.normalization.sarif import cwe_from_tags, owasp_from_tags, parse_sarif
from app.scanners.base import EXCLUDED_DIRS, RunOutcome, Scanner, outcome_from_process, sha256_file


@lru_cache(maxsize=4)
def _known_rule_ids(rules_path: str, ruleset_hash: str) -> frozenset[str]:  # hash keys the cache
    data = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8")) or {}
    return frozenset(r["id"] for r in data.get("rules", []) if isinstance(r, dict) and isinstance(r.get("id"), str))


def portable_rule_id(reported: str, known: frozenset[str]) -> str:
    """Strip the install-path prefix Semgrep adds to rule ids from a local config.

    With ``--config /abs/path/rules.yaml`` Semgrep reports ids such as
    ``D.projects.spa.rules.vendor.python.flask.security...``: the absolute path
    of the ruleset becomes part of every rule id. Left alone, every Semgrep
    fingerprint would change whenever the project directory moves, so every
    finding would be NEW on a teammate's machine. The ruleset's own ids are the
    portable form; the longest one the reported id ends with wins.
    """
    if reported in known:
        return reported
    best = max((k for k in known if reported.endswith("." + k)), key=len, default=None)
    return best or reported


class SemgrepScanner(Scanner):
    name = "semgrep"
    binary = "semgrep"
    tool_dir = "semgrep"

    def _run(self, exe: Path, root: Path, out_dir: Path) -> RunOutcome:
        settings = get_settings()
        notes: list[str] = []
        rules = settings.semgrep_rules
        if rules.is_file():
            config, ruleset_hash = str(rules), sha256_file(rules)
        else:
            config, ruleset_hash = "p/python", None
            notes.append("pinned ruleset snapshot missing; used live registry p/python (not reproducible)")

        report = out_dir / "semgrep.sarif"
        args = [
            str(exe), "scan", "--config", config, "--sarif", "--output", str(report),
            "--metrics=off", "--disable-version-check", "--disable-nosem", "--no-git-ignore",
            "--quiet", "--timeout", "30", "--max-target-bytes", "2000000",
        ]
        for excluded in EXCLUDED_DIRS:
            args += ["--exclude", excluded]
        args.append(".")

        proc = run_tool(args, cwd=root, timeout=settings.scanner_timeout_seconds)
        # 0 = ran (findings or not); 1 = findings with --error (not used); 2+ = failure.
        failure = outcome_from_process(proc.timed_out, proc.returncode, {0, 1}, proc.stderr, self.name)
        if failure:
            failure.ruleset_hash = ruleset_hash
            return failure
        if not report.is_file():
            return RunOutcome([], ToolStatus.ERROR, error="semgrep produced no report", ruleset_hash=ruleset_hash)

        run = parse_sarif(read_capped_file(report), root)
        known = _known_rule_ids(str(rules), ruleset_hash) if ruleset_hash else frozenset()
        findings = [
            NormalizedFinding(
                tool=self.name,
                rule_id=portable_rule_id(r.rule_id, known),
                message=redact(r.message),
                file_path=r.file_path,
                start_line=r.start_line,
                end_line=r.end_line,
                severity=normalise_severity(r.level or r.rule_default_level),
                snippet=redact(r.snippet),
                cwe_reported=cwe_from_tags(r.rule_tags),
                owasp_reported=owasp_from_tags(r.rule_tags),
                native_fingerprint=r.fingerprints.get("matchBasedId/v1"),
            )
            for r in run.results
        ]
        if run.dropped_out_of_root:
            notes.append(f"{run.dropped_out_of_root} result(s) outside the scan root were discarded")
        outcome = RunOutcome(findings, notes=notes, ruleset_hash=ruleset_hash,
                             unverified_scopes={f"file:{p}" for p in run.error_files})
        if not run.execution_successful:
            # Findings that were reported are still evidence; absence is not.
            outcome.status = ToolStatus.ERROR
            outcome.error = "semgrep reported an unsuccessful execution: " + "; ".join(run.notifications[:3])
        return outcome
