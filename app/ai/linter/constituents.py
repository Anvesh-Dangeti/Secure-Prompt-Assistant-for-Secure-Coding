"""A-rules: are the security-sensitive constituents present, and where?

Paper 2 (Cicalese et al., section IV-B) removed one syntactic constituent at a
time from secure-coding prompts and measured the effect on generated code.
The constituents whose removal raised vulnerability rates are the ones checked
here: the entity at risk (WHNP), the condition under which an operation may
proceed (WHADVP/SBAR), the handling directive (VP), the opening sentence, and
late positions. Section V-B proposes a linter for exactly this and notes no
one has built one.

Implementation note, stated plainly: these are pattern checks over the
instruction text, not a constituency parser. They are necessary conditions --
a prompt can mention "parameterised query" and still be a bad prompt -- and the
evaluation measures how well they track verified outcomes (E1, E3).

Only the *instructions* are searched. A name that appears inside the untrusted
code block does not bind the instruction to it, and text in that block is data.
"""

from __future__ import annotations

import re
from dataclasses import replace

from app.ai.delimiting import SplitPrompt
from app.ai.linter.expectation import LintExpectation
from app.ai.linter.report import ERROR, WARNING, LintIssue
from app.ai.linter.text import FENCE_RE, contains_any, first_sentence, mentions, sentences

TASK_RE = re.compile(r"\b(fix|fixes|fixing|remediate|repair|patch|correct|resolve|secure|harden|rewrite|"
                     r"refactor|update|upgrade|change|modify|replace|remove)\b", re.IGNORECASE)
GUARD_RE = re.compile(r"\b(only\s+(if|when|after|once|while)|unless|provided\s+that|as\s+long\s+as|until|"
                      r"before\s+(it|they|its|their|the|this|being|passing|using|it's)|otherwise|"
                      r"if\s+and\s+only\s+if|under\s+(what|which)\s+conditions?)\b", re.IGNORECASE)
SCOPE_RE = re.compile(r"\b((do\s+not|don't|never)\s+(change|modify|touch|alter|rename|edit|refactor)|"
                      r"only\s+(change|modify|edit)|change\s+only|nothing\s+else|no\s+unrelated|"
                      r"(keep|leave)\b[^.\n]{0,60}\bunchanged)\b", re.IGNORECASE)
_IDENT_RE = re.compile(r"`[^`\n]{1,80}`|\b[A-Za-z_]\w*_\w+\b|\b[A-Za-z_][\w.]*\(\)")
_FILE_RE = re.compile(r"\b[\w/.\-]+\.(py|txt|cfg|toml|ini|ya?ml|json)\b")
_OUR_TOKENS = re.compile(r"untrusted_code")


def _identifiers(text: str) -> bool:
    return bool(_IDENT_RE.search(_OUR_TOKENS.sub("", text)))


def _a1(instr: str, exp: LintExpectation) -> tuple[bool | None, LintIssue | None]:
    if exp.bound:
        if not exp.entities:
            return None, None
        if any(mentions(instr, e) for e in exp.entities):
            return True, None
        return False, LintIssue("A1", ERROR, "the instructions never name the value or call at risk ("
                                + ", ".join(f"`{e}`" for e in exp.entities[:4]) + ")", exp.fixits.get("A1"))
    if _identifiers(instr):
        return True, None
    return False, LintIssue("A1", ERROR, "the instructions never name a specific variable or call; say which "
                            "input is unsafe and which call it reaches")


def _a2(instr: str, exp: LintExpectation) -> tuple[bool, LintIssue | None]:
    if GUARD_RE.search(instr):
        return True, None
    return False, LintIssue("A2", ERROR, "no condition says when the operation may proceed (e.g. 'only after "
                            "the value is validated')", exp.fixits.get("A2"))


def _a3(instr: str, exp: LintExpectation) -> tuple[bool | None, LintIssue | None]:
    if not exp.vocabulary:
        return None, LintIssue("A3", WARNING, f"no directive vocabulary for {exp.cwe or 'this weakness'}: the "
                               "handling directive cannot be checked")
    if contains_any(instr, exp.vocabulary):
        return True, None
    sample = ", ".join(f"'{t}'" for t in exp.vocabulary[:3]) if exp.bound else "a concrete mitigation"
    return False, LintIssue("A3", ERROR, f"no handling directive says how to fix it (expected e.g. {sample})",
                            exp.fixits.get("A3"))


def _a4(instr: str, exp: LintExpectation) -> tuple[bool, LintIssue | None]:
    if SCOPE_RE.search(instr):
        return True, None
    return False, LintIssue("A4", ERROR, "nothing forbids unrelated changes; an assistant may rewrite more "
                            "than the flagged code", exp.fixits.get("A4"))


def _a5(opening: str, exp: LintExpectation) -> tuple[bool, LintIssue | None]:
    missing = []
    if not TASK_RE.search(opening):
        missing.append("the task")
    if not contains_any(opening, exp.weakness_terms):
        missing.append("the weakness")
    if exp.bound:
        located = any(mentions(opening, x) for x in (*exp.locations, *exp.entities))
    else:
        located = _identifiers(opening) or bool(_FILE_RE.search(opening))
    if not located:
        missing.append("the location")
    if not missing:
        return True, None
    return False, LintIssue("A5", ERROR, "the opening sentence does not state " + " or ".join(missing)
                            + "; put the task first", exp.fixits.get("A5"))


def _stranded(split: SplitPrompt, preamble: str, pattern_hit) -> bool:  # noqa: ANN001
    """True if a constituent appears only at the end of the prompt."""
    if split.blocks:
        early, late = preamble + "\n" + split.before, split.after
    else:
        parts = sentences(split.instructions)
        if len(parts) < 3:
            return False
        early, late = preamble + "\n" + " ".join(parts[:-1]), parts[-1]
    return pattern_hit(late) and not pattern_hit(early)


def check_constituents(split: SplitPrompt, preamble: str, exp: LintExpectation):
    """Return (issues, {A1..A5: present?}).

    Markdown-fenced code in a hand-written prompt is data too, so it is
    removed before searching, exactly like a delimited block.
    """
    split = replace(split, instructions=FENCE_RE.sub(" ", split.instructions),
                    before=FENCE_RE.sub(" ", split.before), after=FENCE_RE.sub(" ", split.after))
    instr = (preamble + "\n" + split.instructions).strip()
    opening = first_sentence(split.before)
    results = {
        "A1": _a1(instr, exp),
        "A2": _a2(instr, exp),
        "A3": _a3(instr, exp),
        "A4": _a4(instr, exp),
        "A5": _a5(opening, exp),
    }
    issues = [issue for _, issue in results.values() if issue is not None]
    present = {rule: ok for rule, (ok, _) in results.items()}

    checks = {"A2": lambda t: bool(GUARD_RE.search(t)),
              "A3": lambda t: bool(contains_any(t, exp.vocabulary))}
    for rule, hit in checks.items():
        if present[rule] and _stranded(split, preamble, hit):
            issues.append(LintIssue("A6", WARNING, f"the {'guard' if rule == 'A2' else 'handling directive'} "
                                    "appears only at the end of the prompt; state it before the code -- "
                                    "shortening and truncation remove the end first"))
    return issues, present
