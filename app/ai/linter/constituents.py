"""A-rules: are the security-sensitive constituents present, and where?

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), which this application and the published linter
share, so there is one copy of the code. See ``secure_prompt_lint.constituents`` for
the design notes. Re-exported here so the application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.constituents import GUARD_RE, SCOPE_RE, TASK_RE, check_constituents

__all__ = ["GUARD_RE", "SCOPE_RE", "TASK_RE", "check_constituents"]
