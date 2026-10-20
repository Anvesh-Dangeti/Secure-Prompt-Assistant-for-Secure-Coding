"""Combine gate results into one verdict -- failure first, then missing evidence, then a pass.

    any gate FAIL                       -> FIX_REJECTED  (reason: the first failing gate)
    else any gate UNVERIFIED / NOT_RUN  -> UNVERIFIED    (reason: the first gate lacking evidence)
    else                                -> VERIFIED_RESOLVED

NOT_APPLICABLE counts as a pass because the gate states why there was nothing
to check. An empty gate list is UNVERIFIED: no evidence is never a pass.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from app.db.models import Verdict
from app.verification.gates import GateResult, GateStatus


@dataclass(frozen=True)
class Outcome:
    verdict: Verdict
    reason: str | None
    gates: tuple[GateResult, ...]


def decide(gates: Sequence[GateResult]) -> Outcome:
    gates = tuple(gates)
    for g in gates:
        if g.status == GateStatus.FAIL:
            return Outcome(Verdict.FIX_REJECTED, f"gate {g.gate} ({g.title}): {g.detail}", gates)
    for g in gates:
        if g.status in {GateStatus.UNVERIFIED, GateStatus.NOT_RUN}:
            return Outcome(Verdict.UNVERIFIED, f"gate {g.gate} ({g.title}): {g.detail}", gates)
    if not gates:
        return Outcome(Verdict.UNVERIFIED, "no gate was evaluated", gates)
    return Outcome(Verdict.VERIFIED_RESOLVED, None, gates)
