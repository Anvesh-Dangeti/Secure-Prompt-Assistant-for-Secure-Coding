"""Secret redaction for anything that leaves the process or gets persisted.

Used in three places, all with the same rules:

* the logging filter (secrets must never reach log files),
* finding snippets before they are fingerprinted or stored (Bandit's snippet for
  a hard-coded password *is* the password), and
* later, context sent to the LLM.

Redacting before fingerprinting matters for two reasons. First, rotating a
hard-coded secret is not a fix, so the finding's identity must not change when
only the secret's value changes. Second, a truncated hash of a snippet that
contains a low-entropy password is an offline guessing oracle; hashing the
redacted snippet removes it.

Patterns are deliberately conservative: over-redacting a log line costs nothing,
leaking a credential is the failure we are guarding against.
"""

from __future__ import annotations

import re

PLACEHOLDER = "<REDACTED>"

# (pattern, replacement). Order matters: specific token formats first, then the
# generic "name = 'value'" assignment rule.
_RULES: list[tuple[re.Pattern[str], str]] = [
    # PEM private key blocks.
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
     PLACEHOLDER),
    # Credentials embedded in URLs: https://user:pass@host -> https://<REDACTED>@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1" + PLACEHOLDER + "@"),
    # Well-known token formats.
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), PLACEHOLDER),                 # AWS access key id
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), PLACEHOLDER),                # GitHub tokens
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), PLACEHOLDER),              # GitHub fine-grained PAT
    (re.compile(r"\b[sr]k_(?:live|test|prod)_[A-Za-z0-9]{10,}\b"), PLACEHOLDER),  # Stripe
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), PLACEHOLDER),             # Slack
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), PLACEHOLDER),                   # Google API key
    (re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b"), PLACEHOLDER),     # LLM provider keys
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), PLACEHOLDER),  # JWT
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=\-]{8,}"), r"\1" + PLACEHOLDER),
    # Quoted assignment to a secret-looking name: password = "hunter2",
    # {"password": "hunter2"}, config["password"] = "hunter2"
    (re.compile(
        r"(?i)\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key"
        r"|private[_\-]?key|credential|auth)[A-Za-z0-9_]*(?:[\"']\]?)?\s*[:=]\s*)([\"'])([^\"'\n]+)\2"),
     r"\1\2" + PLACEHOLDER + r"\2"),
    # Unquoted key=value pairs as they appear in log lines or query strings.
    (re.compile(
        r"(?i)\b((?:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key)=)([^\s&\"',;]+)"),
     r"\1" + PLACEHOLDER),
]


def redact(text: str | None) -> str:
    """Return ``text`` with every recognised secret replaced by a placeholder."""
    if not text:
        return text or ""
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def mask_secret(text: str, secret: str | None) -> str:
    """Remove a known secret value from ``text``, then apply the generic rules.

    Gitleaks tells us the exact secret string. Masking that literal value is
    precise; its reported column numbers are not reliable enough to slice on.
    """
    if secret and len(secret) >= 4:
        text = text.replace(secret, PLACEHOLDER)
    return redact(text)
