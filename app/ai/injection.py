"""Phrases that read as instructions to a model rather than as code.

Used in two places: the linter warns when such text sits inside an untrusted
code block (it stays delimited as data, but a human should look), and the
Explainer discards a model-written explanation containing it, because that text
would be forwarded into the developer's prompt *outside* the delimiters.

A heuristic, deliberately: it catches the common, copy-pasted forms. The
defences that do not depend on it are the delimiting, the schema validation of
every model answer, and independent scanner verification.
"""

from __future__ import annotations

import re

INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"\bignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?)",
    r"\bdisregard\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding|system)",
    r"\bforget\s+(all\s+|everything\s+)?(you|the)\s+(were\s+told|instructions?)",
    r"\byou\s+are\s+now\b",
    r"\bnew\s+instructions?\s*:",
    r"\bsystem\s+prompt\b",
    r"</?\s*(system|assistant|user|instructions?)\s*>",
    r"^\s*(system|assistant)\s*:",
    r"\b(mark|report|treat)\s+(this|the)\s+(vulnerability|finding|issue)\s+as\s+(fixed|resolved|safe)",
))


def injection_phrases(text: str) -> list[str]:
    """Every suspicious phrase found in ``text`` (empty if none)."""
    hits: list[str] = []
    for pattern in INJECTION_PATTERNS:
        for line in text.splitlines() or [text]:
            m = pattern.search(line)
            if m:
                hits.append(m.group(0).strip())
    return hits
