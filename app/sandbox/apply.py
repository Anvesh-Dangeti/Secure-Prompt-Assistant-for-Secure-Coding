"""Apply a validated fix proposal to a scratch copy -- a text splice, nothing more.

The model saw exactly the context window (``FindingContext.code``) and was
asked for a complete replacement of it, plus any new imports in a separate,
schema-validated list (``output_schema.FixProposal``). So applying it is:

1. replace lines ``window_start..window_end`` with the proposal's code,
   re-indented to the window's original indentation (``ctx.indent``);
2. insert each new import after the module docstring and any ``__future__``
   imports, unless an identical line already exists.

No diff is parsed and nothing is evaluated. Unified diffs were rejected
because small local models produce diffs that do not apply; a whole-window
replacement either applies exactly or is refused. The only file written is
``ctx.file_path`` inside ``root``, confined with ``safe_join``.
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass
from pathlib import Path

from app.ai.context import FindingContext
from app.ai.output_schema import FixProposal
from app.core.config import get_settings
from app.core.paths import PathTraversalError, safe_join


class ApplyError(ValueError):
    """The proposal cannot be applied faithfully -- recorded as a rejected fix, never patched up."""


@dataclass(frozen=True)
class AppliedPatch:
    file_path: str
    window: tuple[int, int]            # the original lines that were replaced
    new_lines: int                     # how many lines replaced them
    imports_added: tuple[str, ...]


def _header_end(tree: ast.Module | None) -> int:
    """Number of leading lines taken by the module docstring and ``from __future__`` imports."""
    if tree is None:
        return 0
    end, body = 0, tree.body
    i = 0
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        end, i = body[0].end_lineno or body[0].lineno, 1
    while i < len(body) and isinstance(body[i], ast.ImportFrom) and body[i].module == "__future__":
        end, i = body[i].end_lineno or body[i].lineno, i + 1
    return end


def apply_proposal(root: Path, ctx: FindingContext, proposal: FixProposal) -> AppliedPatch:
    try:
        path = safe_join(root, *Path(ctx.file_path).parts)
    except PathTraversalError as exc:
        raise ApplyError(str(exc)) from exc
    if path.is_symlink() or not path.is_file():
        raise ApplyError(f"not a regular file: {ctx.file_path}")
    if path.stat().st_size > get_settings().max_context_file_bytes:
        raise ApplyError(f"file too large to patch: {ctx.file_path}")
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApplyError(f"{ctx.file_path} is not UTF-8 text") from exc
    is_python = ctx.file_path.endswith(".py")
    if proposal.imports and not is_python:
        raise ApplyError("imports were proposed for a file that is not Python")

    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    start, end = ctx.window_start, ctx.window_end
    if not 1 <= start <= end <= len(lines):
        raise ApplyError("the context window lies outside the file")
    try:
        header = _header_end(ast.parse(text)) if is_python else 0
    except SyntaxError:
        header = 0

    body = textwrap.dedent(proposal.code.expandtabs(4)).strip("\n").splitlines()
    replacement = [ctx.indent + line if line.strip() else "" for line in body]
    lines[start - 1:end] = replacement
    if end <= header:          # the window sat inside the header: keep the insertion point aligned
        header += len(replacement) - (end - start + 1)

    present = {line.strip() for line in lines}
    added = tuple(imp for imp in dict.fromkeys(proposal.imports) if imp not in present)
    lines[header:header] = list(added)

    path.write_bytes((newline.join(lines) + newline).encode("utf-8"))
    return AppliedPatch(ctx.file_path, (start, end), len(replacement), added)
