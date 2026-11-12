"""Phrases that read as instructions to a model rather than as code.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), which this application and the published linter
share, so there is one copy of the code. See ``secure_prompt_lint.injection`` for
the design notes. Re-exported here so the application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.injection import INJECTION_PATTERNS, injection_phrases

__all__ = ["INJECTION_PATTERNS", "injection_phrases"]
