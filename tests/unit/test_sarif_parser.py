"""SARIF parsing: real recorded output, and every malformed shape fails loudly."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalization.finding import MalformedOutputError
from app.normalization.sarif import cwe_from_tags, owasp_from_tags, parse_sarif

DATA = Path(__file__).resolve().parents[1] / "data"


def _doc(results: list[dict], rules: list[dict] | None = None, invocations: list | None = None) -> str:
    run = {"tool": {"driver": {"name": "t", "rules": rules or []}}, "results": results}
    if invocations is not None:
        run["invocations"] = invocations
    return json.dumps({"version": "2.1.0", "runs": [run]})


def _result(uri: str = "app.py", rule: str = "R1", line: int = 3) -> dict:
    return {"ruleId": rule, "message": {"text": "m"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                "region": {"startLine": line, "snippet": {"text": "x = 1"}}}}]}


def test_recorded_semgrep_output(tmp_path: Path) -> None:
    run = parse_sarif((DATA / "semgrep_flask_vuln_app.sarif").read_text(encoding="utf-8"), tmp_path)
    assert run.execution_successful
    assert len(run.results) == 12
    assert {r.file_path for r in run.results} == {"app.py", "crypto_utils.py"}
    # Semgrep CE's "native fingerprint" is a placeholder for every result.
    assert {r.fingerprints.get("matchBasedId/v1") for r in run.results} == {"requires login"}
    sql = next(r for r in run.results if r.rule_id.endswith("tainted-sql-string"))
    assert cwe_from_tags(sql.rule_tags) == "CWE-704"   # the documented mis-tag
    assert owasp_from_tags(sql.rule_tags) == "A03"


def test_recorded_bandit_output(tmp_path: Path) -> None:
    run = parse_sarif((DATA / "bandit_flask_vuln_app.sarif").read_text(encoding="utf-8"), tmp_path)
    assert len(run.results) == 9
    b602 = next(r for r in run.results if r.rule_id == "B602")
    assert cwe_from_tags(b602.rule_tags) == "CWE-78"
    assert b602.properties["issue_severity"] == "HIGH"
    assert not b602.snippet[:1].isdigit()   # SARIF snippets carry no line numbers


@pytest.mark.parametrize("text", ["", "not json", "[]", '{"runs": {}}', '{"runs": []}',
                                  '{"runs": [{}, {}]}', '{"runs": [{"tool": {}}]}'])
def test_malformed_documents_raise(tmp_path: Path, text: str) -> None:
    with pytest.raises(MalformedOutputError):
        parse_sarif(text, tmp_path)


def test_result_without_rule_id_raises(tmp_path: Path) -> None:
    bad = _result()
    del bad["ruleId"]
    with pytest.raises(MalformedOutputError):
        parse_sarif(_doc([bad]), tmp_path)


def test_result_without_uri_raises(tmp_path: Path) -> None:
    bad = _result()
    del bad["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    with pytest.raises(MalformedOutputError):
        parse_sarif(_doc([bad]), tmp_path)


@pytest.mark.parametrize("uri", ["../../etc/passwd", "../sibling/app.py", "C:/Windows/win.ini", "/etc/shadow"])
def test_paths_outside_the_scan_root_are_dropped(tmp_path: Path, uri: str) -> None:
    run = parse_sarif(_doc([_result(uri=uri), _result(uri="ok.py")]), tmp_path)
    assert [r.file_path for r in run.results] == ["ok.py"]
    assert run.dropped_out_of_root == 1


def test_backslash_and_file_uris_normalise(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    absolute = (tmp_path / "pkg" / "b.py").as_posix()
    run = parse_sarif(_doc([_result(uri="pkg\\a.py"), _result(uri=f"file:///{absolute}")]), tmp_path)
    assert [r.file_path for r in run.results] == ["pkg/a.py", "pkg/b.py"]


def test_unsuccessful_execution_and_error_files_are_reported(tmp_path: Path) -> None:
    invocations = [{"executionSuccessful": False, "toolExecutionNotifications": [
        {"message": {"text": "parse error"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "broken.py"}}}]}]}]
    run = parse_sarif(_doc([], invocations=invocations), tmp_path)
    assert not run.execution_successful
    assert run.error_files == {"broken.py"}


def test_cwe_tag_formats() -> None:
    assert cwe_from_tags(["security", "external/cwe/cwe-259"]) == "CWE-259"
    assert cwe_from_tags(["CWE-89: Improper Neutralization"]) == "CWE-89"
    assert cwe_from_tags(["security"]) is None
    assert owasp_from_tags(["OWASP-A01:2017 - Injection", "OWASP-A03:2021 - Injection"]) == "A03"
