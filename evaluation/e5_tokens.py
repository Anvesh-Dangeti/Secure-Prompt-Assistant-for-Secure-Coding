"""E5 (static part): how small can a remediation prompt get before it loses what makes it secure?

    python -m evaluation.e5_tokens

No model is involved, so the result is deterministic and asserted by a test
(``recorded_results.E5_STATIC``). For each of the 24 real fixture findings it
builds the prompt of every rung on the token ladder and measures what a
developer would paste:

* **S7**  -- ours: explanation, every constituent, and two review turns (RCI);
* **S7a** -- S7's first message alone (no review turns);
* **S7m** -- the minimal prompt: only what the linter requires, compact envelope;
* **S2**  -- the best baseline in the E2 pilot, for reference.

It also splits S7's first message into its nine paragraphs, to show where the
tokens go, and measures the delimited code block on its own: the part no
variant can remove, because it is what the assistant must repair.

The *live* part of E5 -- whether the smaller prompts still produce
scanner-verified fixes, and what a whole conversation costs -- runs the E2
harness with ``--strategies S2,S7,S7a,S7m`` (``evaluation/results/e5_tokens.json``).

Token counts are estimates (about four characters per token, ``app.ai.tokens``):
the developer's own assistant is not metered by us. The live run records the
exact counts the model server reports.
"""

from __future__ import annotations

from statistics import median

from app.ai.delimiting import wrap_untrusted
from app.ai.prompt_builder import build_prompt
from app.ai.tokens import estimate_tokens
from evaluation.e1_mutation import NONCE, ROLES, _paragraphs, contexts

LADDER = ("S7", "S7a", "S7m", "S2")


def _spread(values: list[int]) -> tuple[int, int, int]:
    """(min, median, max), the median rounded half up to a whole token."""
    return min(values), int(median(values) + 0.5), max(values)


def run() -> dict:
    ctxs = contexts()
    first: dict[str, list[int]] = {sid: [] for sid in LADDER}
    typed: dict[str, list[int]] = {sid: [] for sid in LADDER}
    passed: dict[str, int] = {sid: 0 for sid in LADDER}
    parts: dict[str, list[int]] = {role: [] for role in ROLES}
    code: list[int] = []
    for ctx in ctxs:
        for sid in LADDER:
            plan = build_prompt(ctx, sid, nonce=NONCE)
            first[sid].append(plan.lint.tokens)
            typed[sid].append(plan.estimated_tokens)
            passed[sid] += plan.lint.passed
        s7 = build_prompt(ctx, "S7", nonce=NONCE).messages[0]
        for role, paragraph in zip(ROLES, _paragraphs(s7), strict=True):
            parts[role].append(estimate_tokens(paragraph))
        code.append(estimate_tokens(wrap_untrusted(ctx.code, ctx.file_path, ctx.lines_label, NONCE).text))
    return {
        "findings": len(ctxs),
        "passes_lint": passed,
        "first_message": {sid: _spread(v) for sid, v in first.items()},
        "typed": {sid: _spread(v) for sid, v in typed.items()},       # every message the developer pastes
        "s7_parts": {role: int(median(v) + 0.5) for role, v in parts.items()},
        "code_block": _spread(code),
        "s7m_saving_vs_s7a": round(1 - sum(first["S7m"]) / sum(first["S7a"]), 2),
    }


def main() -> None:
    result = run()
    n = result["findings"]
    print(f"E5 token ladder (static) -- {n} real findings, estimated tokens (min / median / max)")
    print(f"  {'strategy':<6} {'passes lint':>12}  {'first message':>17}  {'all typed messages':>19}")
    for sid in LADDER:
        f, t = result["first_message"][sid], result["typed"][sid]
        print(f"  {sid:<6} {result['passes_lint'][sid]:>9}/{n}  {f[0]:>5} {f[1]:>5} {f[2]:>5}  {t[0]:>6} {t[1]:>5} {t[2]:>5}")
    print("\n  S7 first message, median tokens per paragraph:")
    for role, tokens in result["s7_parts"].items():
        print(f"    {role:<24} {tokens:>4}")
    lo, mid, hi = result["code_block"]
    print(f"\n  delimited code block alone: {lo} / {mid} / {hi}")
    print(f"  S7m is {int(result['s7m_saving_vs_s7a'] * 100)}% smaller than S7a over all findings")


if __name__ == "__main__":
    main()
