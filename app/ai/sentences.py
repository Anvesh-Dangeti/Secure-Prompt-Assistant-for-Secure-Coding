"""The sentences a remediation prompt is assembled from.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``libs/secure-prompt-lint``), which publishes the prompt templates this
application generates and measures, so there is one copy of the code. See
``secure_prompt_lint.templates.sentences`` for the design notes. Re-exported here
so the application keeps one import path.

The functions take a ``FindingContext`` and a ``CweGuidance`` directly: the
library reads only their attributes (``lines_label``, ``slots()``,
``render()``...), which both classes provide.
"""

from __future__ import annotations

from secure_prompt_lint.templates.sentences import (
    INERT_COMPACT,
    binding,
    classification,
    directive,
    guard,
    location,
    opening,
    output_contract,
    output_contract_compact,
    scanner_report,
    scope,
    scope_compact,
)

__all__ = ["INERT_COMPACT", "binding", "classification", "directive", "guard", "location", "opening",
           "output_contract", "output_contract_compact", "scanner_report", "scope", "scope_compact"]
