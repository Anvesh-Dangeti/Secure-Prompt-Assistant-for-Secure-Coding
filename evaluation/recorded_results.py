"""Headline results, recorded once, asserted by tests, rendered by the review deck.

Every number presented to the panel comes from here. The integration tests
re-run the real scanners and assert the outcome equals these values
(tests/integration/test_scan_fixture.py, test_lifecycle_scenario.py), so a
number on a slide cannot silently drift from what the code actually does.

Values that depend on the network or on third-party repositories that can
change (the live repository scan) are recorded with their date and are *not*
asserted -- they are labelled as a snapshot wherever they are shown.

Toolchain these were recorded with: Semgrep 1.180.0 (p/python snapshot,
151 rules), Bandit 1.9.4, Gitleaks 8.30.1, pip-audit 2.10.1.
"""

from __future__ import annotations

# ---- fixtures/flask_vuln_app, all four scanners (asserted) -----------------
FIXTURE = {
    "findings": 24,
    "by_tool": {"semgrep": 12, "bandit": 9, "gitleaks": 1, "pip-audit": 2},
    "seeded": 10,
    "detected": 10,
    "in_scope": 24,
    "true_positive_findings": 22,      # B403/B404 import advisories are the 2 FPs
    "semgrep_bandit_agree": (4, 4),    # (both detected, both expected)
}

# ---- six-commit lifecycle scenario (asserted) ------------------------------
LIFECYCLE_KEYS = ("NEW", "STILL_OPEN", "RESOLVED", "REGRESSION", "SUPPRESSED", "UNVERIFIED")
LIFECYCLE = {
    "v1-baseline": ((24, 0, 0, 0, 0, 0), "COMPLETED"),
    "v2-fix-sqli": ((4, 19, 3, 0, 2, 0), "COMPLETED"),
    "v3-refactor": ((0, 23, 0, 0, 2, 0), "COMPLETED"),
    "v4-revert": ((0, 23, 0, 3, 2, 0), "COMPLETED"),
    "v5-secret-gitleaks-down": ((0, 24, 1, 0, 2, 1), "PARTIAL"),
    "v6-gitleaks-back": ((0, 24, 1, 0, 2, 0), "COMPLETED"),
}

# ---- eight-commit developer-mode verification scenario (asserted) -----------
# label -> (verdict, first gate that failed or lacked evidence, findings in the weakness)
VERIFICATION = {
    "v2-stub-ping": ("FIX_REJECTED", "3a", 4),
    "v3-fix-ping": ("VERIFIED_RESOLVED", None, 4),
    "v4-churn-sql": ("FIX_REJECTED", "1", 3),
    "v5-fix-sql-new-route": ("FIX_REJECTED", "2", 2),
    "v6-remove-route": ("VERIFIED_RESOLVED", None, 2),
    "v7-token-gitleaks-down": ("UNVERIFIED", "1", 2),
    "v8-gitleaks-back": ("VERIFIED_RESOLVED", None, 2),
}

# ---- lab mode: recorded model answers replayed through all four gates (asserted)
# evaluation/replays/<name>.json -> (rule of the finding, verdict, first gate that failed)
LAB_REPLAYS = {
    "sqli_good": ("B608", "VERIFIED_RESOLVED", None),
    "sqli_stub": ("B608", "FIX_REJECTED", "3a"),
    "sqli_drops_route": ("B608", "FIX_REJECTED", "3a"),
    "sqli_wrong_behaviour": ("B608", "FIX_REJECTED", "3b"),     # only the behaviour tests can see it
    "cmd_quoted_shell": ("B602", "FIX_REJECTED", "1"),
    "cmd_good": ("B602", "VERIFIED_RESOLVED", None),
}
FIXTURE_BEHAVIOUR_TESTS = 10   # fixtures/flask_vuln_app_tests, all passing on the unmodified fixture

# ---- snapshots (recorded 8 Oct 2026, not asserted) -------------------------
LIVE_VULPY = {
    "url": "https://github.com/fportantier/vulpy",
    "commit": "5249cc8b05a1c37f6b2f757b1cf16a509c327122",
    "findings": 68,
    "by_tool": {"bandit": 51, "semgrep": 16, "gitleaks": 1, "pip-audit": 0},
    "in_scope": 27,
    "scoped_cwes": 6,
    "unpinned_not_audited": 9,
    "seconds": 11,
}
SELF_SCAN = {   # app/ scanned by its own four tools, after the fixes in commit 6dbad3d
    "semgrep": 0, "gitleaks": 0, "pip-audit": 0,
    "bandit_low": 3,          # B404 + 2x B603, inherent to the subprocess wrapper
    "fixed_from_self_scan": 3,  # B607 taskkill path, the Semgrep env-taint it caused, B101 asserts
}
TESTS = 278
