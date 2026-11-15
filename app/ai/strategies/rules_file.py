"""S8 -- rules-file injection: a fixed secure-coding ruleset sent with every request.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``secure_prompt_lint.templates.rules_file``). Its rules are the ``rule``
sentences of the guidance table, exported to the library by
``scripts/export_lint_data.py`` (a test keeps the copies equal). Re-exported
here so the application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.templates.rules_file import RULES_FILE, ruleset, s8

__all__ = ["RULES_FILE", "ruleset", "s8"]
