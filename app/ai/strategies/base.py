"""What a prompting strategy is: a function from one finding's context to messages.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``secure_prompt_lint.templates.base``), so the prompts this application
generates and measures are the published ones. Re-exported here so the
application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.templates.base import Build, Strategy, StrategyInput, compose

__all__ = ["Build", "Strategy", "StrategyInput", "compose"]
