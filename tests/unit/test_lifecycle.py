"""The lifecycle state machine, exhaustively -- and its fail-safe property."""

from __future__ import annotations

import itertools

import pytest

from app.db.models import LifecycleState as S
from app.intelligence.lifecycle import classify_scan, next_state

# (previous, present, verifiable) -> (expected state, unverified)
TABLE = {
    (None, True, True): (S.NEW, False),
    (None, True, False): (S.NEW, False),
    (None, False, True): (None, False),
    (None, False, False): (None, False),
}
for prev in (S.NEW, S.STILL_OPEN, S.REGRESSION):
    TABLE |= {
        (prev, True, True): (S.STILL_OPEN, False),
        (prev, True, False): (S.STILL_OPEN, False),
        (prev, False, True): (S.RESOLVED, False),
        (prev, False, False): (prev, True),
    }
TABLE |= {
    (S.RESOLVED, True, True): (S.REGRESSION, False),
    (S.RESOLVED, True, False): (S.REGRESSION, False),
    (S.RESOLVED, False, True): (S.RESOLVED, False),
    (S.RESOLVED, False, False): (S.RESOLVED, False),
}
for present, verifiable in itertools.product((True, False), repeat=2):
    TABLE[(S.SUPPRESSED, present, verifiable)] = (S.SUPPRESSED, False)


def test_table_covers_every_combination() -> None:
    assert len(TABLE) == 6 * 2 * 2


@pytest.mark.parametrize("key", sorted(TABLE, key=str))
def test_transition(key: tuple) -> None:
    assert next_state(*key) == TABLE[key]


def test_never_resolved_without_verification() -> None:
    """The project's central guarantee, checked over the whole input space."""
    for prev, present in itertools.product([None, *S], (True, False)):
        state, _ = next_state(prev, present, verifiable=False)
        if state == S.RESOLVED:
            assert prev == S.RESOLVED, f"{prev} became RESOLVED without a verifying scan"


def test_never_resolved_while_present() -> None:
    for prev, verifiable in itertools.product([None, *S], (True, False)):
        state, _ = next_state(prev, present=True, verifiable=verifiable)
        assert state != S.RESOLVED


def test_missing_verifiability_entry_fails_safe() -> None:
    (t,) = classify_scan({"fp1": S.STILL_OPEN}, present=set(), verifiable={})
    assert t.to_status == S.STILL_OPEN and t.unverified


def test_classify_scan_mixed() -> None:
    previous = {"open": S.STILL_OPEN, "gone": S.NEW, "back": S.RESOLVED, "fp": S.SUPPRESSED, "blind": S.NEW}
    present = {"open", "back", "fp", "brand-new"}
    verifiable = {"open": True, "gone": True, "back": True, "fp": True, "blind": False}
    result = {t.fingerprint: (t.to_status, t.unverified) for t in classify_scan(previous, present, verifiable)}
    assert result == {
        "open": (S.STILL_OPEN, False),
        "gone": (S.RESOLVED, False),
        "back": (S.REGRESSION, False),
        "fp": (S.SUPPRESSED, False),
        "blind": (S.NEW, True),
        "brand-new": (S.NEW, False),
    }
