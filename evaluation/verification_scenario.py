"""A scripted sequence of developer "commits" to flask_vuln_app that exercises every verification verdict.

Used twice: by ``scripts/demo_verify.py`` (the live demonstration) and by
``tests/integration/test_verification_scenario.py`` (which asserts the exact
verdicts, so the demonstration cannot silently break).

Each step is a complete code state built from the pristine fixture by a set of
edits. It is zipped and ingested through the real upload path, and then one
tracked finding is verified against that scan, exactly as ``verify --source``
does it. These are developer-mode verifications: gates 1, 2 and 3a, with
nothing executed.

    v1  baseline
    v2  ping_host emptied to `pass`          -> FIX_REJECTED   gate 3a: body reduced to a stub
    v3  ping_host fixed (list args, no shell)-> VERIFIED       re-verified against v1, the last scan it was seen in
    v4  SQL line edited, still concatenated  -> FIX_REJECTED   gate 1: same weakness re-reported on the edited code
    v5  SQL parameterised + new os.system    -> FIX_REJECTED   gate 2: the commit introduced a HIGH finding
    v6  the os.system route removed          -> VERIFIED       the SQL fix verified again, now with a clean commit
    v7  token moved to env, Gitleaks DOWN    -> UNVERIFIED     Gitleaks' view of the secret cannot be checked
    v8  same code, Gitleaks back             -> VERIFIED
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

from app.cli import zip_directory
from app.core.scratch import scratch_dir
from app.db.models import TrackedFinding, Verification
from app.db.session import init_db, session_scope
from app.intelligence.lifecycle import OPEN_STATES
from app.scan_service import ScanSummary, scan_zip
from app.scanners import Scanner, all_scanners
from app.verification.service import verify
from evaluation.lifecycle_scenario import (FIXTURE, NEW_ROUTE, SQLI_FIXED, SQLI_VULNERABLE, GitleaksOutage, _edit,
                                           move_token_to_env)

PROJECT = "verification-demo"

PING_VULNERABLE = '    output = subprocess.check_output("ping -c 1 " + host, shell=True)\n    return output\n'
PING_FIXED = ('    output = subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, check=False)\n'
              '    return output.stdout\n')
SQLI_CHURNED = """cursor.execute("SELECT name, email FROM users WHERE id = '" + user_id + "'")"""


# ---- code edits (applied in this fixed order) -------------------------------

def stub_ping(root: Path) -> None:
    """A fake fix: the scanners go quiet because the code is gone."""
    _edit(root / "app.py", '    host = request.args.get("host")\n' + PING_VULNERABLE, "    pass\n")


def fix_ping(root: Path) -> None:
    _edit(root / "app.py", PING_VULNERABLE, PING_FIXED)


def churn_sqli(root: Path) -> None:
    """Not a fix: the query is still built from request data, only differently."""
    _edit(root / "app.py", SQLI_VULNERABLE, SQLI_CHURNED)


def fix_sqli(root: Path) -> None:
    _edit(root / "app.py", SQLI_VULNERABLE, SQLI_FIXED)


def add_new_route(root: Path) -> None:
    _edit(root / "app.py", '\n\nif __name__ == "__main__":', NEW_ROUTE + '\n\nif __name__ == "__main__":')


EDITS: dict[str, Callable[[Path], None]] = {
    "stub_ping": stub_ping,
    "fix_ping": fix_ping,
    "churn_sqli": churn_sqli,
    "fix_sqli": fix_sqli,
    "add_new_route": add_new_route,
    "move_token_to_env": move_token_to_env,
}


@dataclass
class Step:
    label: str
    story: str
    edits: tuple[str, ...]
    verify_rule: str | None = None      # rule-id suffix of the open tracked finding to verify
    gitleaks_down: bool = False


STEPS = [
    Step("v1-baseline", "first scan of the vulnerable app", ()),
    Step("v2-stub-ping", "the assistant 'fixes' command injection by emptying ping_host", ("stub_ping",), "B602"),
    Step("v3-fix-ping", "a real fix: argument list, no shell", ("fix_ping",), "B602"),
    Step("v4-churn-sql", "the SQL line is rewritten -- still concatenating request data", ("fix_ping", "churn_sqli"),
         "B608"),
    Step("v5-fix-sql-new-route", "SQL parameterised, but the same commit adds an os.system() route",
         ("fix_ping", "fix_sqli", "add_new_route"), "B608"),
    Step("v6-remove-route", "a follow-up commit removes the new route", ("fix_ping", "fix_sqli"), "B608"),
    Step("v7-token-gitleaks-down", "the token moves to an environment variable while Gitleaks is unavailable",
         ("fix_ping", "fix_sqli", "move_token_to_env"), "B105", gitleaks_down=True),
    Step("v8-gitleaks-back", "same code, Gitleaks available again",
         ("fix_ping", "fix_sqli", "move_token_to_env"), "B105"),
]


@dataclass
class StepResult:
    step: Step
    summary: ScanSummary
    tracked_id: int | None = None
    verification_id: int | None = None
    verdict: str | None = None
    failed_gate: str | None = None      # first gate that failed or lacked evidence
    reason: str | None = None


def materialise(step: Step, dest: Path) -> None:
    shutil.copytree(FIXTURE, dest)
    for name in EDITS:          # fixed order, independent of the tuple's order
        if name in step.edits:
            EDITS[name](dest)


def _target(rule_suffix: str) -> int:
    """The tracked finding a developer would pick: the latest one of that rule that was open before this scan.

    Fingerprint churn (v4) leaves the original finding RESOLVED and opens a new
    one for the same rule, so "the SQL injection" is whichever is open now --
    or, once fixed, the one most recently seen.
    """
    with session_scope() as s:
        rows = list(s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id.endswith(rule_suffix))
                              .order_by(TrackedFinding.last_seen_scan_id.desc(), TrackedFinding.id.desc())))
        open_rows = [t for t in rows if t.status in OPEN_STATES]
        return (open_rows or rows)[0].id


def run_scenario(on_step: Callable[[StepResult], None] | None = None,
                 scanners_factory: Callable[[], list[Scanner]] = all_scanners) -> list[StepResult]:
    init_db()
    results = []
    for step in STEPS:
        tracked_id = _target(step.verify_rule) if step.verify_rule else None
        scanners = scanners_factory()
        if step.gitleaks_down:
            scanners = [GitleaksOutage() if s.name == "gitleaks" else s for s in scanners]
        with scratch_dir("verify-scenario-") as work:
            materialise(step, work / "code")
            zip_directory(work / "code", work / f"{step.label}.zip")
            summary = scan_zip(PROJECT, work / f"{step.label}.zip", label=step.label, scanners=scanners)
        result = StepResult(step, summary, tracked_id)
        if tracked_id is not None:
            with session_scope() as s:
                row: Verification = verify(s, tracked_id, summary.scan_id)
                result.verification_id, result.verdict, result.reason = row.id, row.verdict.value, row.reason
                result.failed_gate = next((g["gate"] for g in row.gates if g["status"] in {"FAIL", "UNVERIFIED"}),
                                          None)
        results.append(result)
        if on_step:
            on_step(result)
    return results

