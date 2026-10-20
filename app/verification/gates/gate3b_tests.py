"""Gate 3b -- the fixture's behaviour tests still pass on the patched copy (lab mode only).

This is the one place the project executes code that a model wrote, so it is
fenced in on every side:

* it runs only in lab mode, only on our own fixtures, and only after gates 1,
  2 and 3a have passed -- the code is already scanner-clean and structurally
  intact (``sandbox.lab`` enforces the order);
* it runs on a scratch copy, through ``run_tool``: list arguments, a scratch
  working directory, the allowlisted environment (no ``SPA_*`` secrets), a
  timeout with process-tree kill, and refusal to run elevated;
* it uses a separate interpreter (``.tools/fixture``, Flask + pytest only),
  never the application's own environment;
* ``-c <tests>/pytest.ini --rootdir <tests>`` pins pytest's configuration, so
  no ``pytest.ini`` or ``conftest.py`` from outside the copied tests is loaded,
  and ``-P`` stops Python prepending the working directory to ``sys.path``, so
  the only importable code under test is the patched copy on ``PYTHONPATH``.

Residual risk, documented rather than hidden: network access is not blocked.
Container isolation is the Phase 9 option.

The tests live next to the fixture (``<fixture>_tests/``), outside the scanned
tree, so they never change the fixture's scanner baseline.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from app.core.config import PROJECT_ROOT, get_settings
from app.core.redaction import redact
from app.core.subprocess_runner import ToolNotFoundError, UnsafeInvocationError, resolve_executable, run_tool
from app.verification.gates import GateResult, GateStatus

TITLE = "fixture tests"
_EXIT_NO_TESTS = 5


def behaviour_tests_for(source_root: Path) -> Path | None:
    """The behaviour tests of a fixture: the sibling directory ``<name>_tests`` with its own pytest.ini."""
    candidate = source_root.resolve().parent / f"{source_root.resolve().name}_tests"
    return candidate if (candidate / "pytest.ini").is_file() else None


def fixture_python() -> Path | None:
    configured = get_settings().fixture_python
    default = PROJECT_ROOT / ".tools" / "fixture" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    for candidate in ([configured] if configured else []) + [default]:
        if candidate.is_file():
            try:
                return resolve_executable(candidate)
            except (ToolNotFoundError, UnsafeInvocationError):
                continue
    return None


def _summary(stdout: str) -> str:
    lines = [line.strip("= ").strip() for line in stdout.splitlines() if line.strip()]
    return redact(lines[-1])[:200] if lines else "no output"


def run_fixture_tests(code_root: Path, tests_dir: Path | None, work: Path) -> GateResult:
    """Run the behaviour tests in ``tests_dir`` against the code in ``code_root`` (both in scratch)."""
    if tests_dir is None:
        return GateResult("3b", TITLE, GateStatus.UNVERIFIED, "no behaviour tests for this source (<name>_tests/)")
    python = fixture_python()
    if python is None:
        return GateResult("3b", TITLE, GateStatus.UNVERIFIED,
                          "fixture test environment not installed (python scripts/install_fixture_env.py)")
    timeout = get_settings().fixture_test_timeout_seconds
    run_dir = Path(tempfile.mkdtemp(prefix="pytest-", dir=work))
    tests = run_dir / "tests"
    shutil.copytree(tests_dir, tests, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    result = run_tool(
        [str(python), "-P", "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "-c", str(tests / "pytest.ini"), "--rootdir", str(tests), str(tests)],
        cwd=run_dir, timeout=timeout,
        extra_env={"PYTHONPATH": str(code_root), "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if result.timed_out:
        return GateResult("3b", TITLE, GateStatus.FAIL, f"the tests did not finish within {timeout}s")
    summary = _summary(result.stdout)
    if result.returncode == 0:
        return GateResult("3b", TITLE, GateStatus.PASS, summary)
    if result.returncode == 1:
        failed = [redact(line.split(" - ")[0].replace("FAILED ", ""))[:200]
                  for line in result.stdout.splitlines() if line.startswith("FAILED ")]
        return GateResult("3b", TITLE, GateStatus.FAIL, summary, tuple(failed[:10]))
    if result.returncode == _EXIT_NO_TESTS:
        return GateResult("3b", TITLE, GateStatus.UNVERIFIED, "no tests were collected")
    return GateResult("3b", TITLE, GateStatus.UNVERIFIED, f"the test run itself failed (exit {result.returncode})")
