"""Shared test configuration.

Every test runs against a throwaway database and scratch root under pytest's
``tmp_path``, so the suite never touches real data and never leaves clones
behind.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.db.session import reset_engine
from tests._support import TEST_API_KEY

ROOT = Path(__file__).resolve().parents[1]


def _isolated_tool_dirs() -> list[str]:
    sub = "Scripts" if os.name == "nt" else "bin"
    dirs = [ROOT / ".tools" / name / sub for name in ("semgrep", "bandit", "pip-audit")]
    return [str(d) for d in dirs if d.is_dir()]


# Scanners are installed in isolated venvs (scripts/install_scanners.py); expose
# them on PATH for the test session the same way a deployment would.
os.environ["PATH"] = os.pathsep.join([*_isolated_tool_dirs(), os.environ.get("PATH", "")])


@pytest.fixture(autouse=True)
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SPA_SCRATCH_ROOT", str(tmp_path / "scratch"))
    monkeypatch.setenv("SPA_DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    monkeypatch.setenv("SPA_API_KEY", TEST_API_KEY)
    get_settings.cache_clear()
    reset_engine()
    yield tmp_path
    get_settings.cache_clear()
    reset_engine()
