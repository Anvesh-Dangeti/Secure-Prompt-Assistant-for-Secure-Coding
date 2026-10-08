"""The finding lifecycle state machine -- a pure function, so it can be tested exhaustively.

For each fingerprint, given its previous state, whether it is present in this
scan, and whether its absence would be *verifiable*:

    previous                      present      absent+verifiable   absent+NOT verifiable
    ----------------------------  -----------  ------------------  ---------------------
    (never seen)                  NEW          -                   -
    NEW / STILL_OPEN / REGRESSION STILL_OPEN   RESOLVED            unchanged, UNVERIFIED
    RESOLVED                      REGRESSION   RESOLVED            RESOLVED
    SUPPRESSED                    SUPPRESSED   SUPPRESSED          SUPPRESSED

"Verifiable" means the scanner that produced the finding ran successfully in
this scan *and* could examine the finding's file or package. This is the
central fail-safe of the project: **a finding is never marked RESOLVED by a
scan that could not have seen it.** A crashed scanner, a timeout, a file the
parser choked on, or a dependency that became unpinned all look like "the
finding disappeared" -- and none of them is evidence of a fix.

The LLM appears nowhere in this module, and never will: whether a weakness is
resolved is decided only by independent re-scanning.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from app.db.models import LifecycleState as S

OPEN_STATES = frozenset({S.NEW, S.STILL_OPEN, S.REGRESSION})


@dataclass(frozen=True)
class Transition:
    fingerprint: str
    from_status: S | None
    to_status: S
    present: bool
    unverified: bool = False

    @property
    def changed(self) -> bool:
        return self.from_status != self.to_status


def next_state(previous: S | None, present: bool, verifiable: bool) -> tuple[S | None, bool]:
    """Return (new state, unverified flag). ``None`` means 'nothing to track'."""
    if previous is None:
        return (S.NEW, False) if present else (None, False)
    if previous == S.SUPPRESSED:
        return S.SUPPRESSED, False
    if present:
        return (S.REGRESSION if previous == S.RESOLVED else S.STILL_OPEN), False
    if previous == S.RESOLVED:
        return S.RESOLVED, False
    if verifiable:
        return S.RESOLVED, False
    return previous, True


def classify_scan(previous: Mapping[str, S], present: set[str], verifiable: Mapping[str, bool]) -> list[Transition]:
    """Apply ``next_state`` to every fingerprint that is tracked or present.

    ``verifiable`` must have an entry for every previously tracked fingerprint;
    a missing entry is treated as *not* verifiable (fail safe).
    """
    out: list[Transition] = []
    for fp in sorted(set(previous) | present):
        prev = previous.get(fp)
        is_present = fp in present
        state, unverified = next_state(prev, is_present, verifiable.get(fp, False))
        if state is not None:
            out.append(Transition(fp, prev, state, is_present, unverified))
    return out
