"""The safe-subprocess helper enforces every rule it claims to."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from app.core.scratch import scratch_dir
from app.core.subprocess_runner import (
    ToolNotFoundError,
    UnsafeInvocationError,
    resolve_executable,
    run_tool,
)

PY = sys.executable


def test_runs_a_tool_and_captures_output() -> None:
    with scratch_dir() as cwd:
        result = run_tool([PY, "-c", "print('hello')"], cwd=cwd, timeout=30)
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"
    assert not result.timed_out


def test_shell_metacharacters_are_inert_arguments() -> None:
    hostile = "; echo PWNED && whoami | calc & $(id) `id`"
    with scratch_dir() as cwd:
        result = run_tool([PY, "-c", "import sys; print(sys.argv[1])", hostile], cwd=cwd, timeout=30)
    # The program received exactly one literal argument; no shell interpreted it.
    assert result.stdout.strip() == hostile


def test_command_strings_are_rejected() -> None:
    with scratch_dir() as cwd, pytest.raises(UnsafeInvocationError):
        run_tool(f"{PY} -c print(1)", cwd=cwd, timeout=30)  # type: ignore[arg-type]


def test_nul_bytes_are_rejected() -> None:
    with scratch_dir() as cwd, pytest.raises(UnsafeInvocationError):
        run_tool([PY, "-c", "print(1)\x00"], cwd=cwd, timeout=30)


def test_timeout_kills_the_process() -> None:
    started = time.monotonic()
    with scratch_dir() as cwd:
        result = run_tool([PY, "-c", "import time; time.sleep(60)"], cwd=cwd, timeout=2)
    assert result.timed_out
    assert result.returncode is None
    assert time.monotonic() - started < 30


def test_missing_binary_raises_not_found() -> None:
    with scratch_dir() as cwd, pytest.raises(ToolNotFoundError):
        run_tool(["definitely-not-a-real-tool-xyz"], cwd=cwd, timeout=10)


def test_cwd_outside_scratch_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(UnsafeInvocationError):
        run_tool([PY, "-c", "print(1)"], cwd=outside, timeout=10)


def test_binaries_inside_scratch_are_never_executed() -> None:
    # A cloned repository could ship its own "git.exe"; it must never run.
    with scratch_dir() as cwd:
        planted = cwd / ("git.exe" if sys.platform == "win32" else "git")
        planted.write_bytes(b"MZ not really")
        with pytest.raises(UnsafeInvocationError):
            resolve_executable(planted)


def test_output_is_capped() -> None:
    with scratch_dir() as cwd:
        result = run_tool([PY, "-c", "print('x' * 100000)"], cwd=cwd, timeout=30, max_output_bytes=1000)
    assert result.output_truncated
    assert len(result.stdout) == 1000


def test_child_does_not_inherit_application_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_API_KEY", "must-not-leak")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak-either")
    code = "import os; print(os.environ.get('SPA_API_KEY'), os.environ.get('OPENAI_API_KEY'))"
    with scratch_dir() as cwd:
        result = run_tool([PY, "-c", code], cwd=cwd, timeout=30)
    assert result.stdout.strip() == "None None"
