"""S0-S6: the prompting techniques measured by Tony et al. (Paper 3, Table 2), adapted to repair.

The implementation lives in the stand-alone ``secure_prompt_lint`` library
(``secure_prompt_lint.templates.paper3``), so the prompts this application
generates and measures are the published ones. Re-exported here so the
application keeps one import path.
"""

from __future__ import annotations

from secure_prompt_lint.templates.paper3 import OWASP_PRACTICES, PAPER3, RCI_REVIEW, s0, s1, s2, s3, s4, s5, s6

__all__ = ["OWASP_PRACTICES", "PAPER3", "RCI_REVIEW", "s0", "s1", "s2", "s3", "s4", "s5", "s6"]
