"""Fix-its: rewrite a failing prompt so the failing rules pass.

Deterministic insertions only -- no model rewrites the developer's prompt:

* a missing opening anchor (A5) is placed first;
* other missing constituents (A1, A3, A2, A4) go in one paragraph straight
  after the opening, *before* the code, never at the end (A6: the end is what
  shortening and truncation remove first);
* fenced code is re-wrapped in nonce delimiters (B2) and the inert-data
  instruction is placed before it (B3).

Rules with no safe automatic fix (B1 secrets, B4 oversized context, B5) are
left for the developer: silently deleting part of their prompt would be worse.
"""

from __future__ import annotations

from app.ai.delimiting import CLOSE_RE, INERT_INSTRUCTION, OPEN_RE, split_prompt, wrap_untrusted
from app.ai.linter.expectation import LintExpectation
from app.ai.linter.report import LintReport
from app.ai.linter.text import FENCE_RE, first_sentence

_INSERT_ORDER = ("A1", "A3", "A2", "A4")


def _wrap_fences(text: str) -> str:
    def repl(m) -> str:  # noqa: ANN001
        return wrap_untrusted(m.group(1).rstrip("\n"), "pasted", "-").text
    return FENCE_RE.sub(repl, text)


def _head_and_rest(text: str) -> tuple[str, str]:
    """Split before the first paragraph break that precedes any code block."""
    before = split_prompt(text).before
    cut = before.find("\n\n")
    if cut < 0:
        sentence = first_sentence(before)
        cut = before.find(sentence) + len(sentence) if sentence and sentence != before.strip() else len(before)
    return text[:cut].rstrip(), text[cut:].lstrip("\n")


def apply_fixes(text: str, report: LintReport, exp: LintExpectation) -> str:
    """Return ``text`` with every automatically fixable issue fixed."""
    failed = {i.rule for i in report.issues}

    if "B2" in failed and not (OPEN_RE.search(text) or CLOSE_RE.search(text)) and FENCE_RE.search(text):
        text = _wrap_fences(text)
    if ("B3" in failed or "B2" in failed) and OPEN_RE.search(text) and INERT_INSTRUCTION not in text:
        m = OPEN_RE.search(text)
        text = text[:m.start()].rstrip() + "\n\n" + INERT_INSTRUCTION + "\n\n" + text[m.start():]

    missing = [exp.fixits[r] for r in _INSERT_ORDER if r in failed and exp.fixits.get(r)]
    opening = exp.fixits.get("A5") if "A5" in failed else None
    if missing:
        head, rest = _head_and_rest(text)
        text = "\n\n".join(p for p in (head, " ".join(missing), rest) if p.strip())
    if opening:
        text = opening + "\n\n" + text.lstrip()
    return text
