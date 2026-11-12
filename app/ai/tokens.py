"""Token estimation for prompts that have not been sent to a model.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), which this application and the published linter
share, so there is one copy of the code. See ``secure_prompt_lint.tokens`` for
the design notes. Re-exported here so the application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.tokens import CHARS_PER_TOKEN, estimate_tokens

__all__ = ["CHARS_PER_TOKEN", "estimate_tokens"]
