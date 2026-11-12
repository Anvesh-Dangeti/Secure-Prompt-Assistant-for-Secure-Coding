"""B- and C-rules: the prompt's own security and cost.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), which this application and the published linter
share, so there is one copy of the code. See ``secure_prompt_lint.hygiene`` for
the design notes. Re-exported here so the application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.hygiene import INERT_RE, check_hygiene

__all__ = ["INERT_RE", "check_hygiene"]
