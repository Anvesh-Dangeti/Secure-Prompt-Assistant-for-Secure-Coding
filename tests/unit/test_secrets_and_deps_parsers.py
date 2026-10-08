"""Gitleaks and pip-audit adapters: secrets never stored; dependencies parsed safely."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalization.finding import MalformedOutputError
from app.normalization.gitleaks_json import parse_gitleaks
from app.normalization.pip_audit_json import parse_pip_audit
from app.scanners.pip_audit import sanitise_requirements

FAKE_SECRET = "sk_test_" + "ZZtestOnlyNotARealKey000"


def _leak(file: str = "settings.py", line: int = 2) -> dict:
    return {"RuleID": "stripe-access-token", "Description": "Found a Stripe token", "File": file,
            "StartLine": line, "EndLine": line, "Secret": FAKE_SECRET, "Match": FAKE_SECRET + '"',
            "Fingerprint": f"{file}:stripe-access-token:{line}"}


def test_gitleaks_snippet_keeps_variable_name_but_never_the_secret(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text(f'DEBUG = False\nPAYMENT_KEY = "{FAKE_SECRET}"\n', encoding="utf-8")
    findings, dropped = parse_gitleaks(json.dumps([_leak()]), tmp_path)
    assert dropped == 0
    (f,) = findings
    assert FAKE_SECRET not in f.snippet + f.message
    assert f.snippet.startswith("PAYMENT_KEY = ")
    assert f.native_fingerprint is None   # Gitleaks' own fingerprint embeds the line number


def test_gitleaks_secret_with_unusual_format_is_still_masked(tmp_path: Path) -> None:
    odd = "Zq8!unusual#format%value"
    (tmp_path / "x.cfg").write_text(f"opaque_value = {odd}\n", encoding="utf-8")
    entry = _leak(file="x.cfg", line=1) | {"Secret": odd}
    (f,), _ = parse_gitleaks(json.dumps([entry]), tmp_path)
    assert odd not in f.snippet


@pytest.mark.parametrize("text", ["{", '{"a": 1}', '[{"File": "x"}]'])
def test_gitleaks_malformed_raises(tmp_path: Path, text: str) -> None:
    with pytest.raises(MalformedOutputError):
        parse_gitleaks(text, tmp_path)


def test_gitleaks_empty_and_null_reports_are_clean(tmp_path: Path) -> None:
    assert parse_gitleaks("", tmp_path) == ([], 0)
    assert parse_gitleaks("null", tmp_path) == ([], 0)


def test_gitleaks_path_escape_is_dropped(tmp_path: Path) -> None:
    findings, dropped = parse_gitleaks(json.dumps([_leak(file="../../outside.py")]), tmp_path)
    assert findings == [] and dropped == 1


PIP_AUDIT_REPORT = {
    "dependencies": [
        {"name": "flask", "version": "3.1.3", "vulns": []},
        {"name": "pyyaml", "version": "5.3", "vulns": [
            {"id": "PYSEC-2020-96", "fix_versions": ["5.3.1"], "aliases": ["CVE-2020-1747", "GHSA-6757-jp84-gxfx"]},
            {"id": "PYSEC-2021-142", "fix_versions": ["5.4"], "aliases": ["CVE-2020-14343"]},
            {"id": "PYSEC-2021-142", "fix_versions": ["5.4"], "aliases": ["CVE-2020-14343"]},
        ]},
        {"name": "internal-lib", "version": "1.0", "skip_reason": "Dependency not found on PyPI"},
    ],
    "fixes": [],
}


def test_pip_audit_dedupes_and_extracts_cves() -> None:
    findings, skipped = parse_pip_audit(json.dumps(PIP_AUDIT_REPORT), "requirements.txt", {"pyyaml": 6})
    assert [f.vuln_id for f in findings] == ["PYSEC-2020-96", "PYSEC-2021-142"]
    assert findings[0].cve_ids == ["CVE-2020-1747"]
    assert findings[0].start_line == 6 and findings[0].package == "pyyaml"
    assert findings[0].scope_key == "package:pyyaml"
    # A package pip-audit could not check is unverified -- never silently clean.
    assert skipped == {"internal-lib"}


@pytest.mark.parametrize("text", ["", "[]", '{"dependencies": {}}', '{"dependencies": [{"version": "1"}]}'])
def test_pip_audit_malformed_raises(text: str) -> None:
    with pytest.raises(MalformedOutputError):
        parse_pip_audit(text, "requirements.txt", {})


def test_requirements_sanitiser_keeps_only_strict_pins() -> None:
    text = "\n".join([
        "# comment",
        "flask==3.1.3  # web",
        "PyYAML[extra]==5.3 ; python_version >= '3.8'",
        "requests>=2.0",
        "numpy",
        "-r ../../../etc/other.txt",
        "--index-url https://evil.example/simple",
        "-e git+https://example.com/repo.git#egg=pkg",
        "pkg @ https://example.com/pkg.tar.gz",
        "hashed==1.0 \\",
        "    --hash=sha256:" + "a" * 64,
    ])
    out = sanitise_requirements(text)
    assert out.lines == ["flask==3.1.3", "PyYAML==5.3", "hashed==1.0"]
    assert out.unpinned == {"requests", "numpy"}
    assert out.ignored_directives == 4
    assert out.line_of["pyyaml"] == 3 and out.line_of["hashed"] == 10
