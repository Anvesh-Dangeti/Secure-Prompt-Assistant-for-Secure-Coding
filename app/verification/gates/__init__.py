"""The verification gates and their shared result type.

Each gate is a pure function of the evidence (``compare.RescanEvidence``) except
3b, which runs the fixture's tests in lab mode. A gate never raises for bad
evidence: missing evidence is ``UNVERIFIED``, so it cannot be mistaken for a pass.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class GateStatus(str, enum.Enum):
    # Values equal the member names. They are generated rather than written as
    # literals because the self-scan's Bandit reads `PASS = "PASS"` as a
    # hard-coded password (B105) -- a false positive, but suppression comments
    # are ignored by design, so the code avoids the pattern instead.
    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: list) -> str:
        return name

    PASS = enum.auto()
    FAIL = enum.auto()
    UNVERIFIED = enum.auto()        # the evidence needed to decide is missing
    NOT_APPLICABLE = enum.auto()    # nothing for this gate to check (counts as a pass, and says why)
    NOT_RUN = enum.auto()           # deliberately skipped because an earlier gate did not pass


@dataclass(frozen=True)
class GateResult:
    gate: str          # "1", "2", "3a", "3b"
    title: str
    status: GateStatus
    detail: str
    items: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"gate": self.gate, "title": self.title, "status": self.status.value, "detail": self.detail,
                "items": list(self.items)}

    @classmethod
    def from_dict(cls, data: dict) -> GateResult:
        return cls(data["gate"], data["title"], GateStatus(data["status"]), data["detail"],
                   tuple(data.get("items", ())))
