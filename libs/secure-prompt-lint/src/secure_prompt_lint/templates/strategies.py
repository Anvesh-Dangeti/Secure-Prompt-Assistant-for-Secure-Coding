"""The strategy registry: S0-S8 plus the token-ladder variants S7a and S7m."""

from __future__ import annotations

from secure_prompt_lint.templates.base import Strategy
from secure_prompt_lint.templates.ours import OURS
from secure_prompt_lint.templates.paper3 import PAPER3
from secure_prompt_lint.templates.rules_file import RULES_FILE

STRATEGIES: dict[str, Strategy] = {s.id: s for s in (*PAPER3, *OURS, *RULES_FILE)}
#: The nine strategies of the comparison (Tony et al.'s S0-S6, ours, a rules file).
COMPARED: tuple[str, ...] = tuple(f"S{i}" for i in range(9))
#: The token-ladder variants of S7: one message without RCI, and the minimal prompt.
LADDER: tuple[str, ...] = ("S7a", "S7m")
#: The most token-efficient strategy measured (9/10 verified fixes at about 380 tokens per attempt).
RECOMMENDED = "S7m"

#: What the short names in ``Strategy.origin`` refer to.
PAPERS = {
    "Paper 1": "Yan, Vaidya, Zhang and Yao, Guiding AI to Fix Its Own Flaws: An Empirical Study on "
               "LLM-Driven Secure Code Generation, arXiv:2506.23034 (2025)",
    "Paper 2": "Cicalese, Della Porta, Lambiase, Iannone, Hinrichs, Scandariato and Palomba, The Language of "
               "Security: How Prompt Syntax Shapes Secure Code Generation in Open LLMs, arXiv:2607.15937 (2026)",
    "Paper 3": "Tony, Díaz Ferreyra, Mutas, Dhif and Scandariato, Prompting Techniques for Secure Code "
               "Generation: A Systematic Investigation, ACM TOSEM 34(8), Article 225 (2025)",
}

_BY_KEY = {sid.upper(): s for sid, s in STRATEGIES.items()}


def get_strategy(strategy_id: str) -> Strategy:
    key = strategy_id.strip().upper()
    if key not in _BY_KEY:
        raise ValueError(f"unknown strategy {strategy_id!r}; choose one of {', '.join(STRATEGIES)}")
    return _BY_KEY[key]
