"""Deterministic stand-in scanners and a toy app for verification tests (no real scanners needed).

``PatternScanner`` applies one regex per rule, line by line, to every ``.py``
file -- enough to make findings appear, move, churn and disappear exactly as
the test's code edits dictate, through the real scan, persistence, lifecycle
and verification code.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from app.cli import zip_directory
from app.core.scratch import scratch_dir
from app.db.models import ToolStatus
from app.normalization.finding import NormalizedFinding
from app.scan_service import ScanSummary, scan_zip
from app.scanners.base import RunOutcome, Scanner

TOY_APP = '''\
import subprocess

from flask import Flask, request

app = Flask(__name__)
cursor = None


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    return "ok"


@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    return subprocess.check_output("ping " + host, shell=True)
'''
SQL_FIXED = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
SQL_VULNERABLE = '''cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)'''
PING_BODY = '    host = request.args.get("host")\n    return subprocess.check_output("ping " + host, shell=True)\n'

BANDIT_RULES = {"B608": (r"execute\(.*%", "CWE-89", "MEDIUM"), "B602": (r"shell=True", "CWE-78", "HIGH"),
                "B605": (r"os\.system\(", "CWE-78", "HIGH")}
SEMGREP_RULES = {"python.tainted-sql-string": (r"execute\(.*(%|\+)", "CWE-89", "HIGH")}


class PatternScanner(Scanner):
    binary = tool_dir = "pattern"

    def __init__(self, name: str, rules: dict[str, tuple[str, str, str]], status: ToolStatus = ToolStatus.OK,
                 blind: set[str] | None = None) -> None:
        self.name, self.rules, self.status, self.blind = name, rules, status, blind or set()

    def locate(self) -> Path | None:
        return Path(sys.executable)        # never executed: _run is pure Python

    def version(self) -> str | None:
        return "test"

    def _run(self, exe: Path, root: Path, out_dir: Path) -> RunOutcome:
        if self.status != ToolStatus.OK:
            return RunOutcome([], self.status, error=f"{self.name} unavailable")
        findings = []
        for path in sorted(root.rglob("*.py")):
            rel = path.relative_to(root).as_posix()
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                for rule, (pattern, cwe, severity) in self.rules.items():
                    if re.search(pattern, line):
                        findings.append(NormalizedFinding(
                            tool=self.name, rule_id=rule, message=rule, file_path=rel, start_line=number,
                            end_line=number, severity=severity, snippet=line.strip(), cwe_reported=cwe))
        return RunOutcome(findings, unverified_scopes=set(self.blind))


def scanners(semgrep: ToolStatus = ToolStatus.OK, blind: set[str] | None = None) -> list[Scanner]:
    return [PatternScanner("bandit", BANDIT_RULES), PatternScanner("semgrep", SEMGREP_RULES, semgrep, blind)]


def write_app(root: Path, text: str = TOY_APP) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(text, encoding="utf-8")
    return root


def scan(project: str, code: Path, **kw: object) -> ScanSummary:
    with scratch_dir("t-") as work:
        zip_directory(code, work / "code.zip")
        return scan_zip(project, work / "code.zip", scanners=scanners(**kw))   # type: ignore[arg-type]
