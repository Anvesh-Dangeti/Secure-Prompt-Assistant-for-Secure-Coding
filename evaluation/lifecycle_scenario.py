"""A scripted sequence of "commits" to flask_vuln_app that exercises every lifecycle state.

Used twice: by ``scripts/demo_lifecycle.py`` (the live demonstration) and by
``tests/integration/test_lifecycle_scenario.py`` (which asserts the exact
outcome, so the demonstration cannot silently break).

Each step is a *complete code state* built from the pristine fixture by a set
of edits, zipped, and ingested through the real upload path -- the same
validation, scanning, persistence and lifecycle code a user's upload goes
through.

    v1  baseline                         -> everything NEW; 2 false positives suppressed
    v2  SQLi fixed, new cmd-injection    -> SQLi RESOLVED, new weakness NEW
    v3  reformat + "# nosec" comments    -> nothing changes (not a fix, not new)
    v4  SQLi fix reverted                -> REGRESSION
    v5  token moved to env, Gitleaks DOWN-> Bandit's view RESOLVED, Gitleaks' view UNVERIFIED (kept open)
    v6  same code, Gitleaks back         -> Gitleaks' view RESOLVED
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select

from app.cli import zip_directory
from app.core.scratch import scratch_dir
from app.db.models import LifecycleEvent, TrackedFinding
from app.db.session import init_db, session_scope
from app.intelligence.tracking import suppress
from app.scan_service import ScanSummary, scan_zip
from app.scanners import Scanner, all_scanners
from app.scanners.gitleaks import GitleaksScanner

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "flask_vuln_app"
PROJECT = "lifecycle-demo"

SQLI_VULNERABLE = """cursor.execute("SELECT name, email FROM users WHERE id = '%s'" % user_id)"""
SQLI_FIXED = """cursor.execute("SELECT name, email FROM users WHERE id = ?", (user_id,))"""
NEW_ROUTE = '''

@app.route("/cleanup")
def cleanup_upload():
    """Added in the same commit as the SQL fix: a NEW command injection."""
    name = request.args.get("name")
    os.system("rm -f /srv/app/uploads/" + name)
    return "ok"
'''
FALSE_POSITIVE_RULES = {
    "B403": "importing pickle is not itself a vulnerability; the call site (B301) is tracked",
    "B404": "importing subprocess is not itself a vulnerability; the call site (B602) is tracked",
}


# ---- code edits (applied in this fixed order) -------------------------------

def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"scenario edit target not found in {path.name}: {old[:60]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def fix_sqli(root: Path) -> None:
    _edit(root / "app.py", SQLI_VULNERABLE, SQLI_FIXED)


def add_new_weakness(root: Path) -> None:
    _edit(root / "app.py", '\n\nif __name__ == "__main__":', NEW_ROUTE + '\n\nif __name__ == "__main__":')


def move_token_to_env(root: Path) -> None:
    cfg = root / "config.py"
    lines = cfg.read_text(encoding="utf-8").splitlines()
    lines = ["import os" if line.startswith("API_TOKEN = ") else line for line in lines]
    cfg.write_text("\n".join(lines) + '\nAPI_TOKEN = os.environ.get("PAYMENT_API_TOKEN", "")\n', encoding="utf-8")


def reformat_and_silence(root: Path) -> None:
    """Not a fix: shifts every line, changes spacing, adds suppression comments."""
    app = root / "app.py"
    text = app.read_text(encoding="utf-8")
    text = text.replace("import os\n", "# --- refactor: module header ---\n\n\n\n\n\nimport os\n", 1)
    text = text.replace("cursor = conn.cursor()", "cursor   =   conn.cursor( )")
    text = text.replace("shell=True)", "shell=True)  # nosec  # nosemgrep")
    text = text.replace('os.system("rm -f /srv/app/uploads/" + name)',
                        'os.system( "rm -f /srv/app/uploads/"+name )  # nosec')
    app.write_text(text, encoding="utf-8")


EDITS: dict[str, Callable[[Path], None]] = {
    "fix_sqli": fix_sqli,
    "add_new_weakness": add_new_weakness,
    "move_token_to_env": move_token_to_env,
    "reformat_and_silence": reformat_and_silence,
}


class GitleaksOutage(GitleaksScanner):
    """Simulates the secrets scanner being unavailable for one scan."""

    def locate(self) -> Path | None:
        return None


@dataclass
class Step:
    label: str
    story: str
    edits: tuple[str, ...]
    gitleaks_down: bool = False
    suppress_false_positives: bool = False


STEPS = [
    Step("v1-baseline", "first scan of the vulnerable app", ()),
    Step("v2-fix-sqli", "developer parameterises the SQL query -- and adds a new route with os.system()",
         ("fix_sqli", "add_new_weakness")),
    Step("v3-refactor", "reformatting + '# nosec' / '# nosemgrep' comments; no real change",
         ("fix_sqli", "add_new_weakness", "reformat_and_silence")),
    Step("v4-revert", "a later commit reverts the SQL fix",
         ("add_new_weakness", "reformat_and_silence")),
    Step("v5-secret-gitleaks-down", "token moved to an env var while Gitleaks is unavailable",
         ("add_new_weakness", "reformat_and_silence", "move_token_to_env"), gitleaks_down=True),
    Step("v6-gitleaks-back", "same code, Gitleaks available again",
         ("add_new_weakness", "reformat_and_silence", "move_token_to_env")),
]
STEPS[0].suppress_false_positives = True


@dataclass
class Change:
    tracked_id: int
    tool: str
    rule: str
    cwe: str | None
    location: str
    from_status: str | None
    to_status: str
    unverified: bool


@dataclass
class StepResult:
    step: Step
    summary: ScanSummary
    changes: list[Change] = field(default_factory=list)
    suppressed: list[Change] = field(default_factory=list)


def materialise(step: Step, dest: Path) -> None:
    shutil.copytree(FIXTURE, dest)
    for name in EDITS:          # fixed order, independent of the tuple's order
        if name in step.edits:
            EDITS[name](dest)


def _changes(scan_id: int) -> list[Change]:
    with session_scope() as s:
        rows = s.execute(select(LifecycleEvent, TrackedFinding)
                         .join(TrackedFinding, LifecycleEvent.tracked_finding_id == TrackedFinding.id)
                         .where(LifecycleEvent.scan_id == scan_id)).all()
        return [Change(t.id, t.tool, t.rule_id.split(".")[-1], t.cwe, f"{t.file_path}:{t.start_line}",
                       e.from_status.value if e.from_status else None, e.to_status.value, e.unverified)
                for e, t in rows if e.unverified or e.from_status != e.to_status]


def _suppress_false_positives() -> list[Change]:
    out = []
    with session_scope() as s:
        for t in s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id.in_(FALSE_POSITIVE_RULES))):
            previous = t.status.value
            suppress(s, t.id, FALSE_POSITIVE_RULES[t.rule_id])
            out.append(Change(t.id, t.tool, t.rule_id, t.cwe, f"{t.file_path}:{t.start_line}", previous,
                              "SUPPRESSED", False))
    return out


def run_scenario(on_step: Callable[[StepResult], None] | None = None,
                 scanners_factory: Callable[[], list[Scanner]] = all_scanners) -> list[StepResult]:
    init_db()
    results = []
    for step in STEPS:
        scanners = scanners_factory()
        if step.gitleaks_down:
            scanners = [GitleaksOutage() if s.name == "gitleaks" else s for s in scanners]
        with scratch_dir("scenario-") as work:
            materialise(step, work / "code")
            zip_directory(work / "code", work / f"{step.label}.zip")
            summary = scan_zip(PROJECT, work / f"{step.label}.zip", label=step.label, scanners=scanners)
        result = StepResult(step, summary, _changes(summary.scan_id))
        if step.suppress_false_positives:
            result.suppressed = _suppress_false_positives()
        results.append(result)
        if on_step:
            on_step(result)
    return results
