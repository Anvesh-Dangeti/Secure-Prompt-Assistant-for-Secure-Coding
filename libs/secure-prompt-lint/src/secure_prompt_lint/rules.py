"""Extension point: add a lint rule without editing the engine.

    from secure_prompt_lint import LintIssue, WARNING, register_rule

    @register_rule("X1", "names the framework the fix must use")
    def framework_named(ctx):
        if "flask" not in ctx.instructions.lower():
            return [LintIssue("X1", WARNING, "the instructions never name the web framework")]
        return []

A rule receives a read-only ``RuleContext`` (the prompt, its instruction text
with untrusted blocks and fenced code removed, the blocks themselves, the
system preamble and the expectation) and returns the issues it found. Rules
run after the built-in ones, in registration order, and their issues are
sorted after the built-ins in the report.

Built-in rule ids (A1-A7, B1-B5, C1) are reserved. A rule must be a pure
function of its input: the linter's value as evidence comes from being
deterministic -- the same prompt always gets the same report.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from secure_prompt_lint.delimiting import SplitPrompt
from secure_prompt_lint.expectation import LintExpectation
from secure_prompt_lint.report import RULES, LintIssue


@dataclass(frozen=True)
class RuleContext:
    text: str                       # the prompt as given
    instructions: str               # text outside untrusted blocks and code fences, preamble included
    blocks: tuple[str, ...]         # contents of the delimited untrusted blocks
    preamble: str                   # system / rules-file text sent before the prompt
    split: SplitPrompt
    expectation: LintExpectation


Check = Callable[[RuleContext], list[LintIssue]]


@dataclass(frozen=True)
class CustomRule:
    rule_id: str
    description: str
    check: Check


_CUSTOM: dict[str, CustomRule] = {}


def register_rule(rule_id: str, description: str) -> Callable[[Check], Check]:
    """Decorator: register ``check`` under ``rule_id`` (which must not be a built-in id)."""
    if not rule_id or not rule_id.replace("_", "").isalnum():
        raise ValueError(f"rule id {rule_id!r} must be alphanumeric")
    if rule_id in RULES:
        raise ValueError(f"{rule_id} is a built-in rule id")

    def wrap(check: Check) -> Check:
        _CUSTOM[rule_id] = CustomRule(rule_id, description, check)
        return check
    return wrap


def unregister_rule(rule_id: str) -> None:
    _CUSTOM.pop(rule_id, None)


def custom_rules() -> list[CustomRule]:
    return list(_CUSTOM.values())


def describe_rules() -> dict[str, str]:
    """Every rule id with its one-line description, built-ins first."""
    return {**RULES, **{r.rule_id: r.description for r in _CUSTOM.values()}}
