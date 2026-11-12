"""Fix-its: rewrite a failing prompt so the failing rules pass.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), which this application and the published linter
share, so there is one copy of the code. See ``secure_prompt_lint.fixit`` for
the design notes. Re-exported here so the application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.fixit import apply_fixes

__all__ = ["apply_fixes"]
