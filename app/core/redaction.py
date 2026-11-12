"""Secret redaction for anything that leaves the process or gets persisted.

Used in three places, all with the same rules:

* the logging filter (secrets must never reach log files),
* finding snippets before they are fingerprinted or stored (Bandit's snippet for
  a hard-coded password *is* the password), and
* context sent to the LLM, and the linter's no-secret rule (B1).

Redacting before fingerprinting matters for two reasons. First, rotating a
hard-coded secret is not a fix, so the finding's identity must not change when
only the secret's value changes. Second, a truncated hash of a snippet that
contains a low-entropy password is an offline guessing oracle; hashing the
redacted snippet removes it.

The patterns live in the ``secure_prompt_lint`` library (``libs/secure-prompt-lint``)
so the linter's B1 rule and this application's logs and prompts recognise
exactly the same secrets; there is one copy of them.
"""

from __future__ import annotations

from secure_prompt_lint.redaction import PLACEHOLDER, mask_secret, redact

__all__ = ["PLACEHOLDER", "mask_secret", "redact"]
