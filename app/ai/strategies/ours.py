"""Our strategies: S7 and the two token-ladder variants of it (S7a, S7m).

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``secure_prompt_lint.templates.ours``), so the prompts this application
generates and measures are the published ones. Re-exported here so the
application keeps one import path. ``sentences`` is the module the strategies
call, so patching it here patches what they use.
"""

from __future__ import annotations

from secure_prompt_lint.templates import sentences
from secure_prompt_lint.templates.ours import OURS, s7, s7a, s7m

__all__ = ["OURS", "s7", "s7a", "s7m", "sentences"]
