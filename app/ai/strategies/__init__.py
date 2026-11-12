"""The strategy registry: S0-S8 plus the token-ladder variants S7a and S7m, selectable per run."""

from __future__ import annotations

from app.ai.strategies.base import Strategy, StrategyInput
from app.ai.strategies.ours import OURS
from app.ai.strategies.paper3 import PAPER3
from app.ai.strategies.rules_file import RULES_FILE

STRATEGIES: dict[str, Strategy] = {s.id: s for s in (*PAPER3, *OURS, *RULES_FILE)}
DEFAULT_STRATEGY = "S7"
#: The nine strategies of the E2 comparison (Paper 3's S0-S6, ours, rules file).
COMPARED: tuple[str, ...] = tuple(f"S{i}" for i in range(9))
#: The token-ladder variants of S7 (E5): one message without RCI, and the minimal prompt.
LADDER: tuple[str, ...] = ("S7a", "S7m")

__all__ = ["COMPARED", "DEFAULT_STRATEGY", "LADDER", "STRATEGIES", "Strategy", "StrategyInput", "get_strategy"]


_BY_KEY = {sid.upper(): s for sid, s in STRATEGIES.items()}


def get_strategy(strategy_id: str) -> Strategy:
    key = strategy_id.strip().upper()
    if key not in _BY_KEY:
        raise ValueError(f"unknown strategy {strategy_id!r}; choose one of {', '.join(STRATEGIES)}")
    return _BY_KEY[key]
