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

# ---- prompt linter over the 24 real fixture findings (asserted) -------------
# tests/data/flask_vuln_app_findings.json; no model involved -- this measures the prompts, not the fixes.
LINTER = {
    "findings": 24,
    # strategy -> (prompts that pass the linter, mean constituent score rounded to 2 places)
    "by_strategy": {
        "S0": (0, 0.38), "S1": (0, 0.38), "S2": (1, 0.72), "S3": (0, 0.45), "S4": (0, 0.38),
        "S5": (0, 0.38), "S6": (0, 0.38), "S7": (24, 1.0), "S8": (1, 0.71),
        # token-ladder variants (12 Nov): both keep every constituent
        "S7a": (24, 1.0), "S7m": (24, 1.0),
    },
    "s0_score_range": (0.2, 0.6),   # S0 quotes the scanner: Semgrep's messages carry hints, Bandit's do not
    "fixits_repair_s0": 24,         # S0 prompts that pass after the linter's fix-its are applied
    "s7_tokens": (279, 373),        # estimated tokens in S7's first message, min and max
    # As shown at Review 4 and mid-sem. The minimum rose from 255 to 279 on 12 Nov, when the dependency
    # prompts began naming every advisory on the package (finding 23); no other prompt changed.
    "s7_tokens_at_review4": (255, 373),
}

# ---- E1: linter mutation sensitivity (asserted; no model) ---------------------
# evaluation/e1_mutation.py: the S7 first message of each of the 24 real findings, mutated the way a
# developer edits a prompt, linted bound to its finding. failed = an error; flagged = an error or a warning.
E1 = {
    "findings": 24,
    "controls_clean": 24,                       # unmutated S7 prompts: no error, no warning
    "constituent": {"mutants": 168, "failed": 149, "flagged": 168},   # mutants that remove a constituent
    "unchecked": {"mutants": 96, "failed": 0, "flagged": 0},          # no rule covers these: no false alarms
    # operator -> (failed, flagged), each out of 24
    "by_operator": {
        "delete opening": (24, 24), "delete explanation": (0, 0), "delete directive": (9, 24),
        "delete guard": (20, 24), "delete classification": (0, 0), "delete scope": (24, 24),
        "delete inert-data instruction": (24, 24), "delete untrusted code": (0, 0),
        "delete output contract": (0, 0), "genericise directive + guard": (24, 24),
        "truncate to the opening": (24, 24), "undelimit the code": (0, 16),
    },
}
# Before the A7 sentence check that E1 motivated (21 Oct), a deleted directive or guard was flagged only
# 9/24 and 20/24 times: S7's guard restates the mitigation, so A3's vocabulary survived the deletion.
# Historical, not asserted (the linter no longer behaves this way).
E1_BEFORE_A7_SENTENCES = {"delete directive": (9, 9), "delete guard": (20, 20)}

# ---- E2 pilot: S0-S8 live fixes by the local model (recorded 21 Oct 2026) -----------
# evaluation/e2_strategies.py -> evaluation/results/e2_pilot.json. One trial per (seeded weakness, strategy),
# temperature 0, seed 42; every fix rescanned by all four scanners and judged by gates 1, 2, 3a, 3b.
# Needs the model, so tests do not re-run it: they recompute these numbers from the committed per-trial rows.
E2_PILOT = {
    "trials": 90,
    "verified": 59,
    "model": "qwen2.5-coder:7b-instruct",
    "digest": "dae161e27b0e",
    # strategy -> (verified, applicable, ESR, prompt + completion tokens over its ten trials)
    "by_strategy": {
        "S0": (5, 10, 0.5, 3745), "S1": (6, 10, 0.6, 3825), "S2": (9, 10, 0.9, 4252),
        "S3": (7, 10, 0.7, 5016), "S4": (6, 10, 0.6, 3912), "S5": (5, 10, 0.5, 17507),
        "S6": (6, 10, 0.6, 3947), "S7": (7, 10, 0.7, 23356), "S8": (8, 10, 0.8, 6614),
    },
    "failed_at": {"1": 22, "3a": 2, "3b": 7},   # where the 31 rejected fixes were stopped
    "dependency_bumps_rejected": 9,             # every strategy pinned PyYAML 5.3.1; PYSEC-2021-142 needs 5.4
    "strict_imports_reply_failures": 10,        # first run (e2_pilot_strict_imports.json), before the fix
}

# ---- E5 (static): the token ladder over the 24 real findings (asserted; no model) ---------
# evaluation/e5_tokens.py. Estimated tokens, (min, median, max). S7a = S7 without its two review turns;
# S7m = only what the linter requires, compact envelope. "typed" = every message the developer pastes.
E5_STATIC = {
    "findings": 24,
    "passes_lint": {"S7": 24, "S7a": 24, "S7m": 24, "S2": 1},
    "first_message": {"S7": (279, 334, 373), "S7a": (279, 334, 373), "S7m": (142, 199, 234), "S2": (207, 308, 423)},
    "typed": {"S7": (358, 439, 475), "S7a": (279, 334, 373), "S7m": (142, 199, 234), "S2": (207, 308, 423)},
    # S7's first message, median tokens per paragraph
    "s7_parts": {"opening": 28, "explanation": 56, "directive": 38, "guard": 26, "classification": 17,
                 "scope": 37, "inert-data instruction": 47, "untrusted code": 54, "output contract": 35},
    "code_block": (30, 54, 90),       # the delimited code alone: what no variant can remove
    "s7m_saving_vs_s7a": 0.42,
}

# ---- E5 (live): the token ladder on the local model (recorded 12 Nov 2026) ---------------
# python -m evaluation.e2_strategies --strategies S2,S7,S7a,S7m --out evaluation/results/e5_tokens.json
# 10 seeded weaknesses x 4 strategies, same model, settings, scanners and gates as the E2 pilot, after the
# finding-23 fix. Asserted from the committed rows by tests/unit/test_recorded_e5.py.
E5 = {
    "trials": 40,
    "model": "qwen2.5-coder:7b-instruct",
    "digest": "dae161e27b0e",
    # strategy -> (verified, applicable, ESR, prompt + completion tokens over its ten trials)
    "by_strategy": {
        "S7": (8, 10, 0.8, 22201), "S7a": (9, 10, 0.9, 4989), "S7m": (9, 10, 0.9, 3803), "S2": (9, 10, 0.9, 4254),
    },
    "verified_per_1k_tokens": {"S7": 0.36, "S7a": 1.8, "S7m": 2.37, "S2": 2.12},
    "tokens_per_trial": {"S7": 2220, "S7a": 499, "S7m": 380, "S2": 425},   # rounded mean, whole conversation
    "failed_at": {"S7": {"1": 1, "3a": 1}, "S7a": {"3a": 1}, "S7m": {"3a": 1}, "S2": {"1": 1}},
    # Finding 23 fixed: every rung of ours now upgrades PyYAML to 5.4 (S2, whose prompt names no version, does not)
    "dependency_verified": {"S7": True, "S7a": True, "S7m": True, "S2": False},
    # One cell (GT-09, S7) first ended in ERROR -- "provider: model server timed out", an infrastructure
    # failure, not a model answer. It was re-run alone with --resume; the first attempt is kept as
    # evaluation/results/e5_tokens_attempt1.json.
    "infrastructure_reruns": 1,
}

# ---- related functions: evidence from the E2 pilot's 90 trials (asserted; no new run) -------
# evaluation/related_functions.py. Does a fix to one function break the code that calls it?
RELATED = {
    "callers": {"hash_password": ["register"], "make_reset_token": ["register"]},
    "trials_on_helpers_with_callers": 18,
    "verified_on_helpers_with_callers": 13,          # each passed the behaviour tests that exercise `register`
    "rejected_on_helpers_with_callers_by_gate": {"1": 5},   # weakness still present; none broke the caller
    "caller_broken_by_a_verified_fix": 0,
    "scanner_clean_but_behaviour_broken": 7,         # caught only by gate 3b (lab mode)
    "behaviour_broken_by_cwe": {"CWE-79": 5, "CWE-798": 1, "CWE-89": 1},
    # one-function edits whose damage reached the whole module: every test errors, or the file stops parsing
    "module_wide_breaks": {"tests_error": 2, "file_no_longer_parses": 2},
    "module_wide_examples": ["S5 on API_TOKEN", "S5 on download_file", "S5 on get_user", "S7 on greet"],
}

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
TESTS_AT_REVIEW3 = 278
TESTS_AT_REVIEW4 = 637        # the Review 4 pack (21 Oct); that review was cancelled
TESTS = 749
