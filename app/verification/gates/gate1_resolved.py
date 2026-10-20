"""Gate 1 -- the target weakness is resolved.

Passes only if every finding of the weakness (all scanners' views of it, see
``compare``) is absent after the change *and* that absence is verifiable: the
scanner ran successfully and could examine the file or package.

It also fails on fingerprint churn. A fingerprint includes the flagged code, so
editing the flagged line without fixing it gives the same rule a new
fingerprint: the old one disappears and a "new" one appears. Counting that as
a fix would let a cosmetic edit pass, so a "new" finding in the target's
symbol means the weakness is still there when it comes from the same rule, or
names the same CWE at the weakness's severity or above. A lower-severity
advisory with the same CWE (Bandit's B603 "subprocess without shell" after a
real command-injection fix) is not the weakness; gate 2 reports it as a warning.
"""

from __future__ import annotations

from app.verification.compare import FindingRef, RescanEvidence, severity_rank
from app.verification.gates import GateResult, GateStatus

TITLE = "target resolved"


def _churned(ev: RescanEvidence) -> list[FindingRef]:
    rules = {m.rule_id for m in ev.group}
    floor = severity_rank(ev.severity)
    after = ev.symbol_after

    def same_weakness(f: FindingRef) -> bool:
        return f.rule_id in rules or bool(ev.target.cwe and f.cwe == ev.target.cwe
                                          and severity_rank(f.severity) >= floor)

    def in_target(f: FindingRef) -> bool:
        if ev.target.package:
            return (f.package or "").lower() == ev.target.package.lower()
        if f.file_path != ev.target.file_path:
            return False
        # If the symbol is gone or unreadable, anything in the file counts (gate 3a reports the rest).
        return after.contains(f.line) if after is not None and after.span_start is not None else True

    return [f for f in ev.introduced if same_weakness(f) and in_target(f)]


def gate1_resolved(ev: RescanEvidence) -> GateResult:
    still = [m for m in ev.group if ev.transitions[m.fingerprint].present]
    unverified = [m for m in ev.group if ev.transitions[m.fingerprint].unverified]
    churned = _churned(ev)
    where = ev.symbol_before.label if ev.symbol_before else ev.target.file_path
    if still or churned:
        items = [f"still reported: {m.label}" for m in still] + [f"re-reported on changed code: {f.label}"
                                                                  for f in churned]
        detail = (f"{len(still)} of {len(ev.group)} finding(s) still present" if still
                  else f"the same weakness is reported again in {where} on the edited code")
        return GateResult("1", TITLE, GateStatus.FAIL, detail, tuple(items))
    if unverified:
        return GateResult("1", TITLE, GateStatus.UNVERIFIED,
                          f"{len(unverified)} finding(s) absent, but their scanner could not verify {where}",
                          tuple(f"unverifiable: {m.label}" for m in unverified))
    return GateResult("1", TITLE, GateStatus.PASS,
                      f"{len(ev.group)}/{len(ev.group)} finding(s) of {ev.target.cwe or 'the weakness'} "
                      f"gone from {where}", tuple(f"resolved: {m.label}" for m in ev.group))
