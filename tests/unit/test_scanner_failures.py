"""Scanner failure is never mistaken for a clean result."""

from __future__ import annotations

import sys
from pathlib import Path

from app.core.scratch import scratch_dir
from app.core.subprocess_runner import run_tool
from app.db.models import ToolStatus
from app.normalization.finding import MalformedOutputError
from app.pipeline import neutralise_scanner_config, scan_tree
from app.scanners.base import RunOutcome, Scanner, outcome_from_process


class _Fake(Scanner):
    binary = Path(sys.executable).stem
    tool_dir = "none"

    def __init__(self, name: str, behaviour: str) -> None:
        self.name = name
        self.behaviour = behaviour

    def locate(self) -> Path | None:
        return None if self.behaviour == "missing" else Path(sys.executable)

    def version(self) -> str | None:
        return "0.0-test"

    def _run(self, exe: Path, root: Path, out_dir: Path) -> RunOutcome:
        if self.behaviour == "malformed":
            raise MalformedOutputError("garbage")
        if self.behaviour == "crash":
            raise OSError("disk on fire")
        if self.behaviour == "timeout":
            proc = run_tool([str(exe), "-c", "import time; time.sleep(30)"], cwd=root, timeout=1)
            return outcome_from_process(proc.timed_out, proc.returncode, {0}, proc.stderr, self.name) \
                or RunOutcome([])
        if self.behaviour == "exit2":
            proc = run_tool([str(exe), "-c", "import sys; sys.exit(2)"], cwd=root, timeout=30)
            return outcome_from_process(proc.timed_out, proc.returncode, {0, 1}, proc.stderr, self.name) \
                or RunOutcome([])
        return RunOutcome([])


def _scan(*scanners: Scanner):  # noqa: ANN202
    with scratch_dir() as work:
        root, out = work / "src", work / "out"
        root.mkdir()
        out.mkdir()
        (root / "a.py").write_text("x = 1\n")
        return scan_tree(root, out, list(scanners))


def test_each_failure_mode_has_a_non_ok_status() -> None:
    tree = _scan(_Fake("missing", "missing"), _Fake("malformed", "malformed"), _Fake("crash", "crash"),
                 _Fake("timeout", "timeout"), _Fake("exit2", "exit2"), _Fake("fine", "ok"))
    status = {r.tool: r.status for r in tree.results}
    assert status == {
        "missing": ToolStatus.NOT_INSTALLED,
        "malformed": ToolStatus.ERROR,
        "crash": ToolStatus.ERROR,
        "timeout": ToolStatus.TIMEOUT,
        "exit2": ToolStatus.ERROR,
        "fine": ToolStatus.OK,
    }
    assert not tree.all_ok
    # One failing tool never stops the others from running.
    assert tree.result_for("fine").ok


def test_reports_dir_inside_scanned_tree_is_refused() -> None:
    with scratch_dir() as work:
        try:
            scan_tree(work, work / "out", [])
        except ValueError:
            return
    raise AssertionError("scan_tree accepted a report directory inside the scanned tree")


def test_in_repo_scanner_configuration_is_neutralised() -> None:
    with scratch_dir() as root:
        for name in (".semgrepignore", ".gitleaksignore", ".gitleaks.toml", ".bandit"):
            (root / name).write_text("*\n")
        (root / "sub").mkdir()
        (root / "sub" / ".semgrepignore").write_text("*\n")
        (root / "keep.py").write_text("x = 1\n")
        removed = neutralise_scanner_config(root)
        assert sorted(removed) == sorted([".semgrepignore", ".gitleaksignore", ".gitleaks.toml", ".bandit",
                                          "sub/.semgrepignore"])
        assert (root / "keep.py").exists()
