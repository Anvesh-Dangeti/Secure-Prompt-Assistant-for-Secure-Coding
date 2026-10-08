"""Fingerprint stability — the load-bearing property of the lifecycle engine.

A finding's identity must survive code moving around. If it does not, the
lifecycle engine reports the same weakness as RESOLVED and then immediately as
NEW on a commit that never touched it — which would make every regression
statistic in the evaluation chapter meaningless.

This test caught a real defect: Bandit embeds line numbers inside its `code`
field ("22 import os"), so those numbers were reaching the fingerprint and any
inserted line above a finding changed its identity. See
`_strip_bandit_line_numbers` in scripts/demo_scan.py.

Runs standalone (no pytest needed):
    python tests/unit/test_fingerprint_stability.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SCAN = REPO_ROOT / "scripts" / "demo_scan.py"
FIXTURE = REPO_ROOT / "fixtures" / "vuln_demo"

# Inserted above the findings to force every line number below it to shift.
PADDING = ["", "# --- unrelated code added by a later commit ---"] + [""] * 10
INSERT_AFTER_LINE = 30


def _scan(target: Path) -> list[dict]:
    import json

    proc = subprocess.run(
        [sys.executable, str(DEMO_SCAN), str(target), "--json"],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if not proc.stdout.strip():
        raise RuntimeError(f"demo_scan produced no output: {proc.stderr[:400]}")
    return json.loads(proc.stdout)


def _make_shifted_copy(destination: Path) -> None:
    """Copy the fixture with padding inserted, so all findings move down."""
    source = FIXTURE / "vulnerable_app.py"
    lines = source.read_text(encoding="utf-8").splitlines()
    shifted = lines[:INSERT_AFTER_LINE] + PADDING + lines[INSERT_AFTER_LINE:]
    (destination / "vulnerable_app.py").write_text("\n".join(shifted), encoding="utf-8")


def test_fingerprints_survive_line_shifts() -> None:
    before = _scan(FIXTURE)
    assert before, "expected the fixture to produce findings"

    with tempfile.TemporaryDirectory() as tmp:
        shifted_dir = Path(tmp)
        _make_shifted_copy(shifted_dir)
        after = _scan(shifted_dir)

    fp_before = {f["fingerprint"]: f["line"] for f in before}
    fp_after = {f["fingerprint"]: f["line"] for f in after}

    # The same weaknesses are still there, so nothing may be lost or invented.
    false_resolved = set(fp_before) - set(fp_after)
    false_new = set(fp_after) - set(fp_before)

    assert not false_resolved, (
        f"{len(false_resolved)} finding(s) would be falsely reported RESOLVED "
        f"after an unrelated line insertion: {sorted(false_resolved)}"
    )
    assert not false_new, (
        f"{len(false_new)} finding(s) would be falsely reported NEW "
        f"after an unrelated line insertion: {sorted(false_new)}"
    )

    # And the test must actually be exercising the thing it claims to test:
    # at least some line numbers have to have genuinely moved.
    moved = [fp for fp in fp_before if fp_before[fp] != fp_after[fp]]
    assert moved, "no line numbers changed — the test is not exercising a shift"


def test_line_number_is_not_part_of_identity() -> None:
    """Identity is (rule, path, normalised snippet) — never the line number."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from demo_scan import Finding  # noqa: E402

    kwargs = dict(
        tool="bandit",
        rule_id="B602",
        message="subprocess call with shell=True",
        file="vulnerable_app.py",
        severity="HIGH",
        cwe="CWE-78",
        snippet="return subprocess.check_output('ping -c 1 ' + host, shell=True)",
    )
    assert Finding(line=58, **kwargs).fingerprint == Finding(line=999, **kwargs).fingerprint


def test_whitespace_reformatting_does_not_change_identity() -> None:
    """Reformatting is not a fix — identity must survive it."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from demo_scan import Finding  # noqa: E402

    kwargs = dict(
        tool="bandit", rule_id="B303", message="weak MD5",
        file="vulnerable_app.py", line=73, severity="HIGH", cwe="CWE-327",
    )
    tight = Finding(snippet="return hashlib.md5(password.encode()).hexdigest()", **kwargs)
    loose = Finding(snippet="return  hashlib.md5(  password.encode()  ).hexdigest()  \n", **kwargs)
    # Note: only whitespace differs. Token changes SHOULD change identity.
    assert tight.fingerprint == loose.fingerprint


def test_cwe_hierarchy_is_normalised() -> None:
    """Bandit says CWE-259; the project canonicalises to its parent CWE-798.

    Without this, two tools reporting the same hard-coded credential look like
    two different weaknesses, corrupting the inter-tool agreement metric.
    Paper 3 §7.2 makes the same 259/798 parent-child point.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from demo_scan import Finding, canonical_cwe  # noqa: E402

    assert canonical_cwe("CWE-259") == "CWE-798"
    assert canonical_cwe("CWE-89") == "CWE-89"
    assert canonical_cwe(None) is None

    finding = Finding(
        tool="bandit", rule_id="B105", message="Possible hardcoded password",
        file="vulnerable_app.py", line=34, severity="LOW", cwe="CWE-259",
        snippet='DB_PASSWORD = "SuperSecret123!"',
    )
    assert finding.cwe == "CWE-798"          # canonical
    assert finding.cwe_reported == "CWE-259"  # what the tool actually said
    assert finding.owasp.startswith("A07")
    assert finding.in_scope


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(
        (n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)
    ):
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {name}\n        {exc}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"  ERROR {name}\n        {type(exc).__name__}: {exc}")
    print()
    print(f"  {'FAILED' if failures else 'ALL PASSED'}  ({failures} failure(s))")
    raise SystemExit(1 if failures else 0)
