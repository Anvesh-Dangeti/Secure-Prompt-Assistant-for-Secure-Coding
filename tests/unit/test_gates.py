"""Verification gates over synthetic scan views -- every path, and above all: never a false pass.

These are the "findings are never falsely marked resolved" tests for fixes: a
crashed scanner, a blind spot, a cosmetic edit, a stub, or a fix that adds a
new weakness must never come out VERIFIED_RESOLVED.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from app.db.models import Verdict
from app.verification.compare import FindingRef, ScanView, compare
from app.verification.gates import GateResult, GateStatus
from app.verification.gates.gate1_resolved import gate1_resolved
from app.verification.gates.gate2_no_new import gate2_no_new
from app.verification.gates.gate3a_static import gate3a_static
from app.verification.service import static_gates
from app.verification.symbols import (DEPENDENCY, FILE, FILE_MISSING, FILE_SYMBOL, FUNCTION, MISSING, PRESENT,
                                      UNPARSEABLE, SymbolFacts)
from app.verification.verdict import decide

PASS, FAIL, UNVERIFIED, NA = GateStatus.PASS, GateStatus.FAIL, GateStatus.UNVERIFIED, GateStatus.NOT_APPLICABLE


def ref(fp: str, tool: str = "bandit", rule: str = "B608", cwe: str | None = "CWE-89", sev: str = "HIGH",
        path: str = "app.py", line: int | None = 10, package: str | None = None) -> FindingRef:
    return FindingRef(fp, tool, rule, cwe, sev, path, line, package)


def sym(name: str = "get_user", start: int = 8, end: int = 14, kind: str = FUNCTION, path: str = "app.py",
        **kw: object) -> SymbolFacts:
    fields = {"state": PRESENT, "signature": "(user_id)", "decorators": ("app.route('/user')",)} | kw
    return SymbolFacts(path, name, kind, span_start=start, span_end=end, **fields)


def view(*refs: FindingRef, status: dict[str, str] | None = None, blind: dict[str, frozenset[str]] | None = None,
         symbols: tuple[SymbolFacts, ...] = (sym(), sym("ping_host", 20, 26))) -> ScanView:
    return ScanView(findings={r.fingerprint: r for r in refs},
                    tool_status={"bandit": "OK", "semgrep": "OK", "gitleaks": "OK", **(status or {})},
                    blind_spots=blind or {}, symbols={s.key: s for s in symbols})


SQLI_B = ref("sqli-bandit", sev="MEDIUM")
SQLI_S = ref("sqli-semgrep", tool="semgrep", rule="python.tainted-sql-string", line=11)
CMD = ref("cmd", rule="B602", cwe="CWE-78", line=22)
BEFORE = view(SQLI_B, SQLI_S, CMD)


def gates(after: ScanView, before: ScanView = BEFORE, target: str = "sqli-bandit",
          suppressed: frozenset[str] = frozenset()) -> list[GateResult]:
    return static_gates(compare(target, before, after, suppressed))


def statuses(results: list[GateResult]) -> list[GateStatus]:
    return [g.status for g in results]


def test_clean_fix_is_verified() -> None:
    result = gates(view(CMD))
    assert statuses(result) == [PASS, PASS, PASS]
    assert decide(result).verdict == Verdict.VERIFIED_RESOLVED


def test_the_target_is_the_weakness_not_one_scanner_view() -> None:
    ev = compare("sqli-bandit", BEFORE, view(CMD))
    assert {m.fingerprint for m in ev.group} == {"sqli-bandit", "sqli-semgrep"}   # not the CWE-78 one
    assert ev.severity == "HIGH"                                                 # highest in the group
    result = gates(view(SQLI_S, CMD))                    # Bandit satisfied, Semgrep still reports it
    assert result[0].status == FAIL and "1 of 2" in result[0].detail
    assert decide(result).verdict == Verdict.FIX_REJECTED


def test_same_cwe_in_another_function_is_a_different_weakness() -> None:
    other = ref("sqli-elsewhere", line=24)                 # CWE-89, but inside ping_host
    ev = compare("sqli-bandit", view(SQLI_B, other), view(other))
    assert [m.fingerprint for m in ev.group] == ["sqli-bandit"]


@pytest.mark.parametrize("failure", ["ERROR", "TIMEOUT", "NOT_INSTALLED"])
def test_absence_reported_by_a_failed_scanner_is_never_verified(failure: str) -> None:
    result = gates(view(CMD, status={"semgrep": failure}))
    assert result[0].status == UNVERIFIED and "could not verify" in result[0].detail
    assert result[1].status == UNVERIFIED and "semgrep" in result[1].detail
    assert decide(result).verdict == Verdict.UNVERIFIED


def test_absence_in_a_blind_spot_is_never_verified() -> None:
    result = gates(view(CMD, blind={"semgrep": frozenset({"file:app.py"})}))
    assert statuses(result)[:2] == [UNVERIFIED, UNVERIFIED]
    assert decide(result).verdict == Verdict.UNVERIFIED


def test_scanner_missing_from_the_rescan_counts_as_failed() -> None:
    after = view(CMD)
    after = replace(after, tool_status={k: v for k, v in after.tool_status.items() if k != "gitleaks"})
    assert gates(after)[1].status == UNVERIFIED


def test_a_tool_with_nothing_to_scan_does_not_block() -> None:
    assert gates(view(CMD, status={"pip-audit": "SKIPPED"}))[1].status == PASS


def test_churn_same_rule_on_edited_code_is_still_the_weakness() -> None:
    churned = replace(SQLI_B, fingerprint="sqli-bandit-v2")          # same rule, new snippet -> new fingerprint
    result = gates(view(churned, CMD))
    assert result[0].status == FAIL and "re-reported" in result[0].items[0]


def test_same_cwe_at_weakness_severity_from_another_rule_is_still_the_weakness() -> None:
    swapped = ref("raw-sql", tool="semgrep", rule="python.formatted-sql-query", line=12)
    assert gates(view(swapped, CMD))[0].status == FAIL


def test_lower_severity_advisory_with_same_cwe_is_only_a_warning() -> None:
    before = view(CMD)
    advisory = ref("b603", rule="B603", cwe="CWE-78", sev="LOW", line=22)
    result = gates(view(advisory), before=before, target="cmd")
    assert statuses(result) == [PASS, PASS, PASS]
    assert result[1].items == ("warning LOW: bandit B603 app.py:22",)


def test_new_finding_anywhere_at_weakness_severity_blocks() -> None:
    new = ref("os-system", rule="B605", cwe="CWE-78", path="other.py", line=3)
    result = gates(view(CMD, new))
    assert statuses(result)[:2] == [PASS, FAIL]
    assert decide(result).reason.startswith("gate 2")


def test_new_finding_fails_gate_2_even_when_another_scanner_failed() -> None:
    new = ref("os-system", rule="B605", cwe="CWE-78", path="other.py", line=3)
    assert gates(view(CMD, new, status={"semgrep": "ERROR"}))[1].status == FAIL


def test_suppressed_findings_are_neither_new_nor_part_of_the_weakness() -> None:
    noise = ref("b404", rule="B404", cwe="CWE-89", sev="LOW", line=12)
    before = view(SQLI_B, noise)
    ev = compare("sqli-bandit", before, view(noise), suppressed=frozenset({"b404"}))
    assert [m.fingerprint for m in ev.group] == ["sqli-bandit"]
    new_noise = ref("b404-moved", rule="B404", cwe=None, sev="HIGH", path="x.py")
    ev = compare("sqli-bandit", before, view(noise, new_noise), suppressed=frozenset({"b404-moved"}))
    assert ev.introduced == ()


def test_dependency_bumped_to_a_still_vulnerable_version_is_churn() -> None:
    dep = ref("yaml-53", tool="pip-audit", rule="PYSEC-2020-96", cwe="CWE-1395", path="requirements.txt",
              line=None, package="PyYAML")
    still = replace(dep, fingerprint="yaml-54")
    symbols = (sym("pyyaml", 6, 6, kind=DEPENDENCY, path="requirements.txt"),)
    before = view(dep, symbols=symbols)
    after = view(still, symbols=(sym("pyyaml", 6, 6, kind=DEPENDENCY, path="requirements.txt"),))
    assert gates(after, before=before, target="yaml-53")[0].status == FAIL


# ---- gate 3a ------------------------------------------------------------------


BEFORE_SYM = sym()


@pytest.mark.parametrize("after, status, words", [
    (sym(), PASS, "same parameters"),
    (sym(start=30, end=40), PASS, "same parameters"),                        # moved is fine
    (sym(decorators=("app.route('/user')", "login_required")), PASS, ""),    # adding a guard is fine
    (sym(state=FILE_MISSING), FAIL, "deleted"),
    (sym(state=UNPARSEABLE), FAIL, "no longer parses"),
    (sym(state=MISSING), FAIL, "no longer defined"),
    (sym(signature="(user_id, conn)"), FAIL, "parameters changed"),
    (sym(decorators=()), FAIL, "decorator(s) removed"),
    (sym(body_trivial=True), FAIL, "stub"),
    (sym(undefined_names=("sanitize",)), FAIL, "sanitize"),
    (sym(undefined_names=("sanitize",), star_import=True), PASS, ""),        # cannot tell: not a rejection
])
def test_gate3a(after: SymbolFacts, status: GateStatus, words: str) -> None:
    result = gate3a_static(BEFORE_SYM, after)
    assert result.status == status and words in result.detail


def test_gate3a_compares_with_before_not_with_perfection() -> None:
    stub_before = sym(body_trivial=True, undefined_names=("legacy",))
    assert gate3a_static(stub_before, sym(body_trivial=True, undefined_names=("legacy",))).status == PASS


def test_gate3a_missing_evidence_is_unverified() -> None:
    assert gate3a_static(None, sym()).status == UNVERIFIED
    assert gate3a_static(BEFORE_SYM, None).status == UNVERIFIED


def test_gate3a_other_kinds() -> None:
    env = sym(FILE_SYMBOL, 1, 3, kind=FILE, path=".env")
    assert gate3a_static(env, replace(env, state=FILE_MISSING)).status == NA
    dep = sym("pyyaml", 6, 6, kind=DEPENDENCY, path="requirements.txt")
    assert gate3a_static(dep, dep).status == PASS
    assert "no longer listed" in gate3a_static(dep, replace(dep, state=MISSING)).detail


def test_gate_results_are_individually_callable() -> None:
    ev = compare("sqli-bandit", BEFORE, view(CMD))
    assert gate1_resolved(ev).gate == "1" and gate2_no_new(ev).gate == "2"


# ---- verdict ------------------------------------------------------------------


def _g(gate: str, status: GateStatus) -> GateResult:
    return GateResult(gate, "t", status, f"detail {gate}")


def test_verdict_failure_beats_missing_evidence() -> None:
    out = decide([_g("1", UNVERIFIED), _g("2", FAIL)])
    assert out.verdict == Verdict.FIX_REJECTED and out.reason == "gate 2 (t): detail 2"


def test_verdict_not_applicable_counts_as_pass_and_not_run_does_not() -> None:
    assert decide([_g("1", PASS), _g("3b", NA)]).verdict == Verdict.VERIFIED_RESOLVED
    assert decide([_g("1", PASS), _g("3b", GateStatus.NOT_RUN)]).verdict == Verdict.UNVERIFIED


def test_no_evidence_is_never_a_pass() -> None:
    assert decide([]).verdict == Verdict.UNVERIFIED


def test_gate_result_round_trips_through_json() -> None:
    g = GateResult("3a", "t", FAIL, "d", ("a", "b"))
    assert GateResult.from_dict(g.to_dict()) == g
