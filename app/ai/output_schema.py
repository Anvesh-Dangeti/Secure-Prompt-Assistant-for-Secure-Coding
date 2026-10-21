"""The only shape a lab-mode model answer may take -- validated before anything uses it.

The model is asked (and, through the server, constrained) to reply with JSON
``{"code": ..., "imports": [...], "summary": ...}``. Its reply is still
untrusted text, so it is validated here:

* unknown fields are rejected, sizes are capped;
* ``code`` loses a surrounding Markdown fence if the model added one, and
  must not contain the prompt's delimiter nonce (an echo of our markers);
* every ``imports`` entry must parse as exactly one ``import`` / ``from ...
  import`` statement -- the only change allowed outside the replaced window,
  and nothing that could smuggle in other code. A bare dotted module name
  (``os``, ``os.path``) has exactly one reading, ``import os``, and is read
  that way; it is then checked like any other entry. (The E2 pilot found the
  local model writing ``"secrets"`` for ``"import secrets"`` under seven of the nine
  strategies, which measured the output format rather than the fix.)

A reply that fails any check is ``MalformedModelOutput``: recorded as a
rejected fix, never repaired by guessing what the model meant.
"""

from __future__ import annotations

import ast
import json
import keyword
import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

MAX_REPLY_CHARS = 60_000
_FENCE = re.compile(r"^\s*```[^\n]*\n(.*?)\n?```\s*$", re.DOTALL)
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")


def _as_statement(line: str) -> str:
    """``os`` -> ``import os``; anything else is returned unchanged for the statement check."""
    if _MODULE.fullmatch(line) and not any(keyword.iskeyword(part) for part in line.split(".")):
        return f"import {line}"
    return line


class MalformedModelOutput(ValueError):
    """The model's reply is not a valid fix proposal."""


class FixProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=20_000)
    imports: list[str] = Field(default_factory=list, max_length=10)
    summary: str = Field(default="", max_length=1_000)

    @field_validator("code")
    @classmethod
    def _unfence(cls, value: str) -> str:
        m = _FENCE.match(value)
        value = m.group(1) if m else value
        if not value.strip():
            raise ValueError("code is empty")
        return value

    @field_validator("imports")
    @classmethod
    def _single_import_statements(cls, values: list[str]) -> list[str]:
        clean = []
        for raw in values:
            line = _as_statement(raw.strip())
            if not line or "\n" in line or ";" in line or len(line) > 200:
                raise ValueError(f"not a single import statement: {raw!r}")
            try:
                body = ast.parse(line).body
            except SyntaxError as exc:
                raise ValueError(f"import does not parse: {raw!r}") from exc
            if len(body) != 1 or not isinstance(body[0], (ast.Import, ast.ImportFrom)):
                raise ValueError(f"not an import statement: {raw!r}")
            clean.append(line)
        return clean


FIX_SCHEMA: dict = FixProposal.model_json_schema()


def parse_fix_proposal(text: str, nonce: str | None = None) -> FixProposal:
    if len(text) > MAX_REPLY_CHARS:
        raise MalformedModelOutput("reply too long")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise MalformedModelOutput("reply is not JSON") from exc
    try:
        proposal = FixProposal.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first.get("loc", ())) or "reply"
        raise MalformedModelOutput(f"{where}: {first.get('msg', 'invalid')}") from exc
    if nonce and nonce in proposal.code:
        raise MalformedModelOutput("reply echoes the untrusted-code delimiter")
    return proposal
