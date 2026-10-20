"""The developer-mode CLI loop: scan-zip -> (fix) -> verify --source -> verifications (stand-in scanners)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select

from app import pipeline
from app.cli import main
from app.db.models import TrackedFinding
from app.db.session import session_scope
from tests._verify_support import SQL_FIXED, SQL_VULNERABLE, TOY_APP, scanners, write_app


@pytest.fixture
def code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(pipeline, "all_scanners", scanners)
    return write_app(tmp_path / "code")


def _target() -> int:
    with session_scope() as s:
        return s.scalars(select(TrackedFinding).where(TrackedFinding.rule_id == "B608")).first().id


def test_verify_loop(code: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan-zip", str(code), "--project", "dev"]) == 0
    target = _target()
    write_app(code, TOY_APP.replace(SQL_VULNERABLE, SQL_FIXED))
    capsys.readouterr()
    assert main(["verify", str(target), "--source", str(code)]) == 0
    out = capsys.readouterr().out
    assert "verdict: VERIFIED_RESOLVED" in out and "developer mode never executes repository code" in out
    assert main(["verifications", str(target)]) == 0
    assert "VERIFIED_RESOLVED" in capsys.readouterr().out


def test_rejected_fix_exits_non_zero(code: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["scan-zip", str(code), "--project", "dev"])
    target = _target()
    churned = """cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")"""   # still injectable
    write_app(code, TOY_APP.replace(SQL_VULNERABLE, churned))
    capsys.readouterr()
    assert main(["verify", str(target), "--source", str(code)]) == 1
    assert "FIX_REJECTED" in capsys.readouterr().out


def test_usage_errors(code: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["scan-zip", str(code), "--project", "dev"])
    target = _target()
    assert main(["verify", str(target), "--scan", "1"]) == 2          # nothing before scan 1
    assert "no 'before'" in capsys.readouterr().err
    assert main(["verify", str(target), "--rescan"]) == 2             # a ZIP project has no repository
    assert main(["verify", "9999", "--scan", "1"]) == 2
    assert main(["verifications", "9999"]) == 2
