"""Delimiting untrusted repository code inside a prompt (prompt-injection defence).

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), which this application and the published linter
share, so there is one copy of the code. See ``secure_prompt_lint.delimiting`` for
the design notes. Re-exported here so the application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.delimiting import (
    CLOSE_RE,
    INERT_INSTRUCTION,
    OPEN_RE,
    SplitPrompt,
    UntrustedBlock,
    new_nonce,
    split_prompt,
    wrap_untrusted,
)

__all__ = ["CLOSE_RE", "INERT_INSTRUCTION", "OPEN_RE", "SplitPrompt", "UntrustedBlock", "new_nonce", "split_prompt", "wrap_untrusted"]
