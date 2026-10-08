"""End-to-end: all four real scanners against the seeded fixture.

Skipped (not failed) when a scanner is not installed, so the unit suite stays
runnable anywhere; on the project machine all four are present.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from app.core.scratch import scratch_dir
from app.pipeline import TreeScan, scan_tree
from app.scanners import all_scanners
from evaluation.ground_truth import load_ground_truth, score

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "flask_vuln_app"
FIXTURE_SECRET = "sk_test_4eC39HqLyjWDarjtT1zdp7dcFAKE00"

pytestmark = [
    pytest.mark.scanners,
    pytest.mark.skipif(not all(s.is_available() for s in all_scanners()), reason="scanners not installed"),
]


def _scan_copy(mutate=None) -> TreeScan:  # noqa: ANN001
    with scratch_dir("it-") as work:
        root, out = work / "src", work / "out"
        out.mkdir()
        shutil.copytree(FIXTURE, root)
        if mutate:
            mutate(root)
        return scan_tree(root, out)


@pytest.fixture(scope="module")
def baseline() -> TreeScan:
    from app.core.config import get_settings
    from app.db.session import reset_engine

    # Module-scoped: run the real scanners once for the read-only assertions.
    mp = pytest.MonkeyPatch()
    tmp = Path(__import__("tempfile").mkdtemp())
    mp.setenv("SPA_SCRATCH_ROOT", str(tmp / "scratch"))
    get_settings.cache_clear()
    reset_engine()
    try:
        yield _scan_copy()
    finally:
        mp.undo()
        get_settings.cache_clear()
        shutil.rmtree(tmp, ignore_errors=True)


def test_all_scanners_run_cleanly(baseline: TreeScan) -> None:
    assert {r.tool: r.status.value for r in baseline.results} == {
        "semgrep": "OK", "bandit": "OK", "gitleaks": "OK", "pip-audit": "OK"}
    assert all(r.version for r in baseline.results)
    assert baseline.result_for("semgrep").ruleset_hash, "pinned ruleset hash must be recorded"


def test_every_seeded_weakness_is_detected_by_its_expected_tools(baseline: TreeScan) -> None:
    report = score(load_ground_truth(FIXTURE), baseline.findings, {r.tool for r in baseline.results if r.ok})
    assert report.recall == 1.0
    for seed in report.seeds:
        assert seed.seeded.expected_detectors <= seed.detected_by, seed.seeded.id


def test_no_raw_secret_anywhere_in_findings(baseline: TreeScan) -> None:
    for f in baseline.findings:
        blob = " ".join(map(str, vars(f).values()))
        assert FIXTURE_SECRET not in blob, f"{f.tool} {f.rule_id} leaked the secret"


def test_cves_come_only_from_pip_audit(baseline: TreeScan) -> None:
    assert all(not f.cve_ids for f in baseline.findings if f.tool != "pip-audit")
    deps = [f for f in baseline.findings if f.tool == "pip-audit"]
    assert {"CVE-2020-1747", "CVE-2020-14343"} <= {c for f in deps for c in f.cve_ids}


def test_identity_survives_shifts_reformatting_and_suppression_comments(baseline: TreeScan) -> None:
    def mutate(root: Path) -> None:
        app = root / "app.py"
        lines = app.read_text(encoding="utf-8").splitlines()
        lines = lines[:20] + ["", "# unrelated change in a later commit"] + [""] * 10 + lines[20:]
        text = "\n".join(lines)
        # Suppression comments written by "the developer" (or an AI fix).
        text = text.replace("shell=True)", "shell=True)  # nosec  # nosemgrep")
        text = text.replace('cursor.execute("SELECT', 'cursor.execute(  "SELECT')
        app.write_text(text + "\n", encoding="utf-8")
        cfg = root / "config.py"
        cfg.write_text(cfg.read_text(encoding="utf-8").replace('"\n', '"  # gitleaks:allow\n'), encoding="utf-8")
        # In-repo attempts to switch the scanners off.
        (root / ".semgrepignore").write_text("app.py\n")
        (root / ".gitleaksignore").write_text("config.py:stripe-access-token:10\n")

    after = _scan_copy(mutate)
    before_fps = {f.fingerprint for f in baseline.findings}
    after_fps = {f.fingerprint for f in after.findings}
    assert before_fps - after_fps == set(), "a weakness would be falsely reported RESOLVED"
    assert after_fps - before_fps == set(), "a weakness would be falsely reported NEW"
    assert sorted(after.neutralised) == [".gitleaksignore", ".semgrepignore"]
