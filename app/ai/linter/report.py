"""Lint results: issues, constituent outcomes, and the score used in the evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

RULES: dict[str, str] = {
    # A -- security constituents (Paper 2 sections IV-B and V-B)
    "A1": "entity binding: names the input or call at risk",
    "A2": "condition / guard: states when the operation may proceed",
    "A3": "handling directive: states how the value must be handled",
    "A4": "scope constraint: forbids unrelated changes",
    "A5": "opening anchor: task, weakness and location in sentence one",
    "A6": "no stranded constraint: guard and directive not only at the end",
    "A7": "no silent shortening: nothing lost from the generated prompt",
    # B -- the prompt's own security (threat model: App <-> LLM)
    "B1": "no secret-like value in the prompt",
    "B2": "untrusted code delimited and intact",
    "B3": "inert-data instruction before untrusted code",
    "B4": "untrusted code within the data-minimisation budget",
    "B5": "no instruction-like text inside untrusted code",
    # C -- cost
    "C1": "within the token budget",
}
CONSTITUENTS = ("A1", "A2", "A3", "A4", "A5")
ERROR, WARNING = "error", "warning"


@dataclass(frozen=True)
class LintIssue:
    rule: str
    severity: str
    message: str
    fix: str | None = None       # a sentence that would satisfy the rule, if one is known

    def to_dict(self) -> dict[str, object]:
        return {"rule": self.rule, "severity": self.severity, "message": self.message, "fix": self.fix}


@dataclass(frozen=True)
class LintReport:
    issues: tuple[LintIssue, ...]
    #: A1-A5 -> True (present) / False (missing) / None (not checkable for this finding)
    constituents: Mapping[str, bool | None] = field(default_factory=dict)
    tokens: int = 0
    bound: bool = False

    @property
    def errors(self) -> list[LintIssue]:
        return [i for i in self.issues if i.severity == ERROR]

    @property
    def warnings(self) -> list[LintIssue]:
        return [i for i in self.issues if i.severity == WARNING]

    @property
    def passed(self) -> bool:
        return not self.errors

    @property
    def constituent_score(self) -> float:
        """Share of checkable constituents present -- the linter variable in E2/E3."""
        checkable = [v for v in self.constituents.values() if v is not None]
        return sum(checkable) / len(checkable) if checkable else 0.0

    def failed(self, rule: str) -> bool:
        return any(i.rule == rule for i in self.issues)

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed, "bound": self.bound, "tokens": self.tokens,
            "constituent_score": round(self.constituent_score, 3),
            "constituents": dict(self.constituents),
            "issues": [i.to_dict() for i in self.issues],
        }
