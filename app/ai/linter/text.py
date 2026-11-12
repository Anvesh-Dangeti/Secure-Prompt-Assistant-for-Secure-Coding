"""Small text helpers shared by the lint rules.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), which this application and the published linter
share, so there is one copy of the code. See ``secure_prompt_lint.text`` for
the design notes. Re-exported here so the application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.text import FENCE_RE, contains_any, first_sentence, looks_like_code, mentions, sentences

__all__ = ["FENCE_RE", "contains_any", "first_sentence", "looks_like_code", "mentions", "sentences"]
