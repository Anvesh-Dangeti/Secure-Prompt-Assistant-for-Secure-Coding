"""S0-S6: the prompting techniques measured by Tony et al. (Paper 3, Table 2), adapted to repair.

Paper 3 phrased each technique for *generating* code from a task description.
Here the task is repairing a scanner finding, so each template keeps the
technique's defining cue and wraps it around the scanner's own report:

* S0 baseline      -- the raw scanner output only ("direct feedback", Paper 1)
* S1 naive-secure  -- adds "make sure the code is secure"
* S2 CWE-specific  -- names the CWE and gives MITRE's mitigation
* S3 comprehensive -- a general OWASP secure-coding checklist
* S4 zero-shot CoT -- S1 plus "Let's think step by step"
* S5 RCI           -- S1, then "find security problems", then "improve"
* S6 persona       -- "Act as a software security expert" first

Paper 3's expectations (S5 best, S6 worst) are a self-check on this harness.
"""

from __future__ import annotations

from app.ai import sentences
from app.ai.strategies.base import Strategy, StrategyInput, compose

OWASP_PRACTICES = (
    "Follow OWASP secure-coding practices: validate all input on the server against an allowlist; encode "
    "output for the context it is used in; use parameterised queries for database access; do not pass user "
    "input to operating-system commands; store passwords only as salted hashes from a strong algorithm; use a "
    "cryptographically secure random generator; keep secrets out of source code; validate file paths before "
    "use; do not deserialise untrusted data; disable debugging in production; and keep components up to date."
)
RCI_REVIEW = "Review your previous answer and find security problems with it."


def _task(inp: StrategyInput, suffix: str = "") -> str:
    return f"Fix the problem that a static analyser reported in {sentences.location(inp.ctx)}{suffix}."


def s0(inp: StrategyInput):
    return None, [compose(_task(inp), [sentences.scanner_report(inp.ctx)], inp)]


def s1(inp: StrategyInput):
    opening = _task(inp, ", and make sure the code is secure")
    return None, [compose(opening, [sentences.scanner_report(inp.ctx)], inp)]


def s2(inp: StrategyInput):
    g = inp.guidance
    opening = f"Fix {sentences.location(inp.ctx)} so that it no longer contains security weakness {g.cwe} ({g.name})."
    mitre = f"MITRE's mitigation for {g.cwe}: {g.render('mitre', inp.ctx.slots())}"
    return None, [compose(opening, [sentences.scanner_report(inp.ctx), mitre], inp)]


def s3(inp: StrategyInput):
    opening = _task(inp, ", following secure-coding best practices")
    return None, [compose(opening, [sentences.scanner_report(inp.ctx), OWASP_PRACTICES], inp)]


def s4(inp: StrategyInput):
    opening = _task(inp, ", and make sure the code is secure")
    return None, [compose(opening, [sentences.scanner_report(inp.ctx), "Let's think step by step."], inp)]


def s5(inp: StrategyInput):
    _, first = s1(inp)
    improve = "Based on the problems you found, improve your answer. " + sentences.output_contract(inp.ctx)
    return None, [first[0], RCI_REVIEW, improve]


def s6(inp: StrategyInput):
    task = _task(inp, ", and give the output a software security expert would give")
    return None, [compose("Act as a software security expert.", [task, sentences.scanner_report(inp.ctx)], inp)]


PAPER3 = [
    Strategy("S0", "Baseline", "Paper 1 direct feedback; Paper 3 baseline", "raw scanner output, no security cue", s0),
    Strategy("S1", "Naive-secure", "Paper 3 Table 2", "asks for secure code", s1),
    Strategy("S2", "CWE-specific", "Paper 3 Table 2; MITRE CWE", "names the CWE and MITRE's mitigation", s2),
    Strategy("S3", "Comprehensive", "Paper 3 Table 2; OWASP", "general OWASP secure-coding checklist", s3),
    Strategy("S4", "Zero-shot CoT", "Paper 3 Table 2", "naive-secure plus 'think step by step'", s4),
    Strategy("S5", "RCI", "Paper 3 Table 2", "answer, criticise, improve (3 turns)", s5),
    Strategy("S6", "Persona", "Paper 3 Table 2", "'act as a software security expert'", s6),
]
