"""B- and C-rules: the prompt's own security and cost.

These follow the project's threat model for the App <-> LLM boundary rather
than Paper 2: a prompt must not carry secrets to a third-party model, must
keep repository code delimited as data with an instruction saying so, must stay
within the data-minimisation budget, and should not be inflated beyond what
the fix needs (the developer pays for those tokens).

They matter most for developer-edited prompts: a developer who pastes a whole
file, or a .env value, into an assistant has just sent it to a vendor.
"""

from __future__ import annotations

import re

from app.ai.delimiting import CLOSE_RE, OPEN_RE, SplitPrompt
from app.ai.injection import injection_phrases
from app.ai.linter.expectation import LintExpectation
from app.ai.linter.report import ERROR, WARNING, LintIssue
from app.ai.linter.text import FENCE_RE, looks_like_code
from app.ai.tokens import estimate_tokens
from app.core.redaction import redact

INERT_RE = re.compile(
    r"\b((do\s+not|don't|never)\s+(follow|obey|execute|carry\s+out|act\s+on)\b[^.\n]{0,60}"
    r"\b(instructions?|requests?|comments?|directives?)|treat\s+(it|them|this|that|the\s+code)\b[^.\n]{0,40}"
    r"\bas\s+(inert\s+)?data)", re.IGNORECASE)


def check_hygiene(text: str, preamble: str, split: SplitPrompt, exp: LintExpectation) -> tuple[list[LintIssue], int]:
    issues: list[LintIssue] = []
    full = (preamble + "\n" + text).strip()

    # B1 -- a secret in the prompt reaches a third-party model and its logs.
    if redact(full) != full:
        issues.append(LintIssue("B1", ERROR, "the prompt contains a secret-like value; it would be sent to the "
                                "model provider -- replace it with a placeholder"))

    delimited = bool(OPEN_RE.search(text) or CLOSE_RE.search(text))
    fenced = [m.group(1) for m in FENCE_RE.finditer(text)]
    code_segments = list(split.blocks) if delimited else fenced

    # B2 -- delimiters intact; code present but not delimited.
    if delimited and not split.well_formed:
        issues.append(LintIssue("B2", ERROR, "the untrusted-code markers are broken (unclosed, or the content "
                                "contains its own delimiter)"))
    elif not delimited and (fenced or looks_like_code(split.instructions)):
        issues.append(LintIssue("B2", WARNING, "code is pasted without untrusted-data delimiters; comments in it "
                                "can act as instructions to the model (--fix wraps fenced code)"))

    # B3 -- the model must be told the delimited block is data.
    if code_segments and not INERT_RE.search(preamble + "\n" + split.instructions):
        issues.append(LintIssue("B3", ERROR if delimited else WARNING,
                                "no instruction tells the model to treat the pasted code as data and ignore "
                                "instructions inside it"))

    # B4 -- data minimisation: never a whole file.
    for segment in code_segments:
        lines = len(segment.splitlines())
        if lines > exp.max_block_lines:
            issues.append(LintIssue("B4", ERROR, f"a code block has {lines} lines; send only the flagged function "
                                    f"or at most {exp.max_block_lines} lines around the finding"))
            break

    # B5 -- instruction-like text inside the code (stays delimited, but a human should look).
    phrases = [p for segment in code_segments for p in injection_phrases(segment)]
    if phrases or split.imitation_markers:
        shown = ", ".join(f"'{p}'" for p in phrases[:3]) or "marker-like text"
        issues.append(LintIssue("B5", WARNING, f"the pasted code contains instruction-like text ({shown}); it "
                                "is delimited as data, but review it before sending"))

    # C1 -- cost. An estimate: the developer's assistant is not metered by us.
    tokens = estimate_tokens(full)
    if tokens > exp.token_budget:
        issues.append(LintIssue("C1", WARNING, f"about {tokens} tokens, above the budget of {exp.token_budget}; "
                                "trim context that the fix does not need"))
    return issues, tokens
