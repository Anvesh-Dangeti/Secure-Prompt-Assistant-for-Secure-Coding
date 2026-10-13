"""Small text helpers shared by the lint rules."""

from __future__ import annotations

import re

# A sentence ends at . ! ? followed by whitespace and a capital/quote/backtick,
# at a blank line, or before a bullet. Dotted names (cursor.execute) and
# versions (5.3.1) never split because no whitespace follows their dots.
_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z`\"'(\[<])|\n\s*\n|\n(?=\s*(?:[-*•]|\d+[.)])\s)")

FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_CODE_LINE = re.compile(r"^\s*(def |class |import |from \S+ import |return\b|if .+:\s*$|for .+:\s*$|@\w|"
                        r"[A-Za-z_][\w.\[\]'\"]*\s*=[^=])")


def sentences(text: str) -> list[str]:
    return [s.strip() for s in _SPLIT.split(text or "") if s and s.strip()]


def first_sentence(text: str) -> str:
    found = sentences(text)
    return found[0] if found else ""


def mentions(text: str, name: str) -> bool:
    """Does ``text`` name ``name`` (or, for a dotted call, its final attribute)?"""
    candidates = [name]
    last = name.rsplit(".", 1)[-1]
    if "." in name and len(last) >= 4:
        candidates.append(last)
    return any(re.search(rf"(?<![\w]){re.escape(c)}(?![\w])", text) for c in candidates)


def contains_any(text: str, terms: tuple[str, ...] | list[str]) -> list[str]:
    """Terms that occur in ``text`` starting at a word boundary (case-insensitive).

    Word-*start* matching lets a stem cover its inflections ("parameteris"
    matches "parameterised") without matching inside another word ("salt" must
    not be satisfied by "unsalted", which says the opposite).
    """
    lowered = text.lower()
    return [t for t in terms if t and re.search(rf"(?<![a-z0-9_]){re.escape(t)}", lowered)]


def looks_like_code(text: str) -> bool:
    """At least two lines that look like Python statements."""
    return sum(1 for line in text.splitlines() if _CODE_LINE.match(line)) >= 2
