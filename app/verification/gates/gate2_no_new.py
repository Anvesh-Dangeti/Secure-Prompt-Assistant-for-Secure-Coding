"""Gate 2 -- the change introduced no new finding at the weakness's severity or above.

The comparison is commit-level: a finding present after the change and absent
before it counts wherever it is, because a coding assistant's edits are not
always local. Lower-severity new findings are reported as warnings but do not
block (trading a HIGH weakness for a LOW advisory is still progress).

Fail safe: if any scanner did not run successfully, "nothing new" cannot be
claimed -- a dead scanner reports nothing -- so the gate is UNVERIFIED. The
same holds if the after-scan could not examine the target's own file.
"""

from __future__ import annotations

from app.verification.compare import RescanEvidence, severity_rank
from app.verification.gates import GateResult, GateStatus

TITLE = "no new findings"


def gate2_no_new(ev: RescanEvidence) -> GateResult:
    floor = severity_rank(ev.severity)
    blocking = [f for f in ev.introduced if severity_rank(f.severity) >= floor]
    warnings = [f for f in ev.introduced if severity_rank(f.severity) < floor]
    if blocking:
        return GateResult("2", TITLE, GateStatus.FAIL,
                          f"{len(blocking)} new finding(s) at {ev.severity} or above",
                          tuple(f"new {f.severity}: {f.label}" for f in blocking))
    if ev.failed_tools:
        return GateResult("2", TITLE, GateStatus.UNVERIFIED,
                          f"scanner(s) did not run successfully: {', '.join(ev.failed_tools)}")
    if ev.target_blind:
        return GateResult("2", TITLE, GateStatus.UNVERIFIED,
                          f"the rescan could not examine {ev.target.scope_key.split(':', 1)[1]}")
    detail = f"no new finding at {ev.severity} or above"
    if warnings:
        detail += f"; {len(warnings)} lower-severity new finding(s)"
    return GateResult("2", TITLE, GateStatus.PASS, detail, tuple(f"warning {f.severity}: {f.label}" for f in warnings))
