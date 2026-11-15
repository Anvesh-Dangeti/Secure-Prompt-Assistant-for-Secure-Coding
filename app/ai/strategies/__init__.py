"""The strategy registry: S0-S8 plus the token-ladder variants S7a and S7m, selectable per run.

The strategies are the prompt templates published in the stand-alone
``secure_prompt_lint`` library (``secure_prompt_lint.templates``), so there is one
copy of them; this package re-exports the registry and keeps the application's
default.
"""

from __future__ import annotations

from secure_prompt_lint.templates.strategies import COMPARED, LADDER, STRATEGIES, get_strategy

from app.ai.strategies.base import Strategy, StrategyInput

DEFAULT_STRATEGY = "S7"

__all__ = ["COMPARED", "DEFAULT_STRATEGY", "LADDER", "STRATEGIES", "Strategy", "StrategyInput", "get_strategy"]
