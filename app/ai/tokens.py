"""Token estimation for prompts that have not been sent to a model.

About four characters per token is the usual rule of thumb for BPE tokenisers
on English and code. It is an *estimate*, used for the linter's budget rule and
for developer-mode prompts that go to an assistant we cannot meter. Lab-mode
results record the exact counts the model server reports instead.
"""

from __future__ import annotations

import math

CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text or "") / CHARS_PER_TOKEN)
