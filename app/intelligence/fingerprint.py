"""Finding identity that survives code moving around.

The lifecycle engine decides RESOLVED / NEW / REGRESSION by comparing
fingerprints between scans, so a fingerprint must change when -- and only
when -- the weakness itself changes.

**Never in the material:**

* the line number -- inserting a line above a finding is not a fix;
* whitespace -- reformatting is not a fix (``f( x )`` == ``f(x)``);
* comment-only lines inside a multi-line match -- documenting code is not a fix;
* the absolute scan path -- every scan runs in a fresh scratch directory;
* a raw secret -- snippets are redacted *before* hashing, so rotating a
  hard-coded secret keeps its identity (rotation is not a fix) and the hash
  cannot be used to brute-force a weak password offline.

**Native fingerprints** are preferred only when they are real. Semgrep CE
emits ``matchBasedId/v1: "requires login"`` for *every* finding (verified on
1.180.0); treating that as identity would collapse all Semgrep findings into
one. Gitleaks' fingerprint embeds the line number. Both are rejected.

**Collisions** within one scan (the same rule matching identical text twice in
one file) are disambiguated by an occurrence index in line order, the same
approach Semgrep's own matchBasedId uses.
"""

from __future__ import annotations

import hashlib
import io
import re
import textwrap
import tokenize
from collections import defaultdict

from app.normalization.finding import NormalizedFinding

_PLACEHOLDERS = {"", "requires login", "none", "null", "n/a"}
_NATIVE_OK = re.compile(r"^[A-Za-z0-9+/=_\-]{16,128}$")
_FP_LEN = 32  # hex chars of SHA-256 kept (128 bits)
_LAYOUT_TOKENS = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
                  tokenize.DEDENT, tokenize.ENDMARKER}


def native_is_valid(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() not in _PLACEHOLDERS and bool(_NATIVE_OK.match(value.strip()))


def _without_comments(snippet: str) -> str:
    """Remove every comment, including trailing ones, using Python's tokenizer.

    Trailing comments matter: ``# nosec``, ``# nosemgrep`` and ``gitleaks:allow``
    are comments. If they changed a finding's identity, adding one would look
    like a fix (old fingerprint RESOLVED) plus an unrelated NEW finding. A
    tokenizer -- not a regex -- is needed because ``#`` inside a string literal
    is not a comment. Snippets that are not tokenizable on their own (a match
    starting mid-statement) fall back to dropping comment-only lines.
    """
    try:
        tokens = tokenize.generate_tokens(io.StringIO(textwrap.dedent(snippet) + "\n").readline)
        return " ".join(t.string for t in tokens if t.type not in _LAYOUT_TOKENS)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return "\n".join(line for line in snippet.splitlines() if not line.strip().startswith("#"))


def normalise_snippet(snippet: str) -> str:
    """Remove comments, then strip *all* whitespace."""
    return re.sub(r"\s+", "", _without_comments(snippet))


def derived_fingerprint(finding: NormalizedFinding) -> str:
    if finding.package and finding.vuln_id:
        # A dependency weakness is (file, package, vulnerability). The version is
        # excluded: bumping to another still-vulnerable version is not a fix.
        material = f"{finding.tool}|{finding.file_path}|{finding.package.lower()}|{finding.vuln_id}"
    else:
        material = f"{finding.tool}|{finding.rule_id}|{finding.file_path}|{normalise_snippet(finding.snippet)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:_FP_LEN]


def _native_for(finding: NormalizedFinding) -> str | None:
    if finding.tool == "gitleaks":
        return None  # Gitleaks' fingerprint contains the line number.
    return finding.native_fingerprint if native_is_valid(finding.native_fingerprint) else None


def assign_fingerprints(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Set ``fingerprint``/``fingerprint_source`` on every finding, in place."""
    for f in findings:
        native = _native_for(f)
        if native:
            f.fingerprint = hashlib.sha256(f"{f.tool}|native|{native}".encode()).hexdigest()[:_FP_LEN]
            f.fingerprint_source = "native"
        else:
            f.fingerprint = derived_fingerprint(f)
            f.fingerprint_source = "derived"

    groups: dict[str, list[NormalizedFinding]] = defaultdict(list)
    for f in findings:
        groups[f.fingerprint].append(f)
    for fp, members in groups.items():
        if len(members) < 2:
            continue
        members.sort(key=lambda m: (m.start_line or 0, m.end_line or 0))
        for index, member in enumerate(members[1:], start=2):
            member.fingerprint = hashlib.sha256(f"{fp}#{index}".encode()).hexdigest()[:_FP_LEN]
    return findings
