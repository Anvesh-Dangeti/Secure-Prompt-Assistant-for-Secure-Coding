"""The developer-mode workflow through the real CLI: findings -> explain -> prompt -> lint -> fix."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import cli_ai
from app.cli import main
from app.db.models import Finding, LifecycleState, Project, Scan, SourceType, TrackedFinding
from app.db.session import init_db, session_scope
from app.normalization.finding import NormalizedFinding
from app.ai.providers import ScriptedProvider
from tests._ai_support import FIXTURE, recorded_findings


def _persist(f: NormalizedFinding, project_id: int, scan_id: int, session) -> int:  # noqa: ANN001
    session.add(Finding(
        scan_id=scan_id, tool=f.tool, rule_id=f.rule_id, fingerprint=f.fingerprint,
        fingerprint_source=f.fingerprint_source, severity=f.severity, cwe=f.cwe, cwe_reported=f.cwe_reported,
        owasp=f.owasp, cve_ids=f.cve_ids, in_scope=f.in_scope, file_path=f.file_path, start_line=f.start_line,
        end_line=f.end_line, message=f.message, snippet=f.snippet, package=f.package,
        package_version=f.package_version, fix_versions=f.fix_versions))
    tracked = TrackedFinding(
        project_id=project_id, fingerprint=f.fingerprint, tool=f.tool, rule_id=f.rule_id, cwe=f.cwe,
        severity=f.severity, file_path=f.file_path, start_line=f.start_line, scope_key=f.scope_key,
        status=LifecycleState.NEW, first_seen_scan_id=scan_id, last_seen_scan_id=scan_id)
    session.add(tracked)
    session.flush()
    return tracked.id


@pytest.fixture
def ids() -> dict[str, int]:
    """Tracked-finding id per rule suffix, as `findings` would list them after a scan."""
    init_db()
    out: dict[str, int] = {}
    with session_scope() as session:
        project = Project(name="demo", source_type=SourceType.ZIP)
        session.add(project)
        session.flush()
        scan = Scan(project_id=project.id, source_type=SourceType.ZIP)
        session.add(scan)
        session.flush()
        for f in recorded_findings():
            out.setdefault(f.rule_id.rsplit(".", 1)[-1], _persist(f, project.id, scan.id, session))
    return out


def _run(capsys: pytest.CaptureFixture, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_prompt_command_prints_a_passing_s7(ids, capsys) -> None:  # noqa: ANN001
    code, out, _ = _run(capsys, "prompt", str(ids["B608"]), "--source", str(FIXTURE))
    assert code == 0
    assert "Fix the SQL injection (CWE-89) in `get_user`" in out
    assert "lint: PASS  constituents 100%" in out


def test_prompt_json_and_every_strategy(ids, capsys) -> None:  # noqa: ANN001
    for sid in ("S0", "S5", "S8"):
        code, out, _ = _run(capsys, "prompt", str(ids["B602"]), "--source", str(FIXTURE), "--strategy", sid, "--json")
        data = json.loads(out)
        assert code == 0 and data["strategy"] == sid and data["lint"]["bound"] is True
    assert data["system"].startswith("Follow these secure-coding rules")


def test_prompt_to_file(ids, capsys, tmp_path: Path) -> None:  # noqa: ANN001
    out_file = tmp_path / "prompt.txt"
    code, _, _ = _run(capsys, "prompt", str(ids["B311"]), "--source", str(FIXTURE), "--out", str(out_file))
    assert code == 0 and "secrets module" in out_file.read_text(encoding="utf-8")


def test_explain(ids, capsys) -> None:  # noqa: ANN001
    code, out, _ = _run(capsys, "explain", str(ids["B301"]), "--source", str(FIXTURE))
    assert code == 0 and "`pickle.loads`" in out and "(template)" in out


def test_shortened_developer_prompt_fails_then_fix_passes(ids, capsys, tmp_path: Path) -> None:  # noqa: ANN001
    prompt = tmp_path / "mine.txt"
    prompt.write_text("fix the command injection in ping_host\n\n```python\n"
                      "output = subprocess.check_output(\"ping -c 1 \" + host, shell=True)\n```\n", encoding="utf-8")
    base = ["lint-prompt", str(prompt), "--finding", str(ids["B602"]), "--source", str(FIXTURE)]
    code, out, _ = _run(capsys, *base)
    assert code == 1 and "lint: FAIL" in out and "fix: Call the program with an argument list" in out
    code, out, _ = _run(capsys, *base, "--fix")
    assert code == 0 and "lint: PASS" in out and "<untrusted_code" in out
    code, _, _ = _run(capsys, *base, "--report")
    assert code == 0


def test_unbound_lint_from_stdin(capsys, monkeypatch) -> None:  # noqa: ANN001
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("please make my code better"))
    code, out, _ = _run(capsys, "lint-prompt", "-", "--json")
    report = json.loads(out)
    assert code == 1 and report["bound"] is False and not report["passed"]


def test_changed_checkout_warns(ids, capsys, tmp_path: Path) -> None:  # noqa: ANN001
    for name in ("app.py", "config.py", "crypto_utils.py"):
        (tmp_path / name).write_text((FIXTURE / name).read_text(encoding="utf-8"), encoding="utf-8")
    app = tmp_path / "app.py"
    app.write_text(app.read_text(encoding="utf-8").replace("% user_id", "% (user_id,)"), encoding="utf-8")
    code, _, err = _run(capsys, "prompt", str(ids["B608"]), "--source", str(tmp_path))
    assert code == 0 and "differs from the scanned version" in err


def test_unknown_finding_and_missing_source_are_errors(ids, capsys, tmp_path: Path) -> None:  # noqa: ANN001
    assert _run(capsys, "prompt", "9999", "--source", str(FIXTURE))[0] == 2
    assert _run(capsys, "prompt", str(ids["B608"]), "--source", str(tmp_path / "nope"))[0] == 2


def test_propose_runs_the_lab_conversation_without_applying(ids, capsys, monkeypatch) -> None:  # noqa: ANN001
    fix = json.dumps({"code": "def f():\n    pass", "imports": [], "summary": "s"})
    monkeypatch.setattr(cli_ai, "get_provider", lambda name=None: ScriptedProvider(["a", "b", fix]))
    code, out, _ = _run(capsys, "propose", str(ids["B608"]), "--source", str(FIXTURE))
    data = json.loads(out)
    assert code == 0 and data["calls"] == 3 and data["proposal"]["code"].startswith("def f")
    assert "nothing has been applied" in data["note"]
    assert (FIXTURE / "app.py").read_text(encoding="utf-8").count("% user_id") == 1   # fixture untouched


def test_propose_reports_model_failure(ids, capsys, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(cli_ai, "get_provider", lambda name=None: ScriptedProvider(["not json"]))
    code, out, _ = _run(capsys, "propose", str(ids["B608"]), "--source", str(FIXTURE), "--strategy", "S0")
    assert code == 1 and json.loads(out)["error"].startswith("malformed")


def test_strategies_and_providers_listing(capsys) -> None:  # noqa: ANN001
    code, out, _ = _run(capsys, "strategies")
    assert code == 0 and out.count("\n") == 9 and "[must pass lint]" in out
    code, out, _ = _run(capsys, "providers")
    assert code == 0 and "template  available" in out
