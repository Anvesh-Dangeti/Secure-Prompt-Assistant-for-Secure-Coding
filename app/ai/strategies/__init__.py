"""The strategy registry: S0-S8, selectable per run."""

from __future__ import annotations

from app.ai.strategies.base import Strategy, StrategyInput
from app.ai.strategies.ours import OURS
from app.ai.strategies.paper3 import PAPER3
from app.ai.strategies.rules_file import RULES_FILE

STRATEGIES: dict[str, Strategy] = {s.id: s for s in (*PAPER3, *OURS, *RULES_FILE)}
DEFAULT_STRATEGY = "S7"

__all__ = ["DEFAULT_STRATEGY", "STRATEGIES", "Strategy", "StrategyInput", "get_strategy"]


def get_strategy(strategy_id: str) -> Strategy:
    key = strategy_id.strip().upper()
    if key not in STRATEGIES:
        raise ValueError(f"unknown strategy {strategy_id!r}; choose one of {', '.join(STRATEGIES)}")
    return STRATEGIES[key]
