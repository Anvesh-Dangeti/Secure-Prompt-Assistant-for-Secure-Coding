"""Minimal, redacted source context for one finding -- the only code that may reach an LLM.

Data minimisation (threat model, App <-> LLM):

* a function no longer than ``max_context_lines`` is sent whole, so lab mode can
  replace it as one unit; a longer one is clipped to ``context_radius`` lines
  either side of the finding; a module-level finding sends only its statement;
  a dependency finding sends only its requirements line;
* comments and docstrings are removed. They are natural language that whoever
  controls the repository can address to the model (prompt injection), a model
  does not need them to repair code, and in our fixture they name the weakness
  -- a security cue that would contaminate the S0 negative control;
* the result is redacted with the same rules as the logs.

The file is read from a directory the caller names (the developer's checkout,
or a lab-mode scratch copy). The repo-relative path reported by the scan is
untrusted, so it is confined with ``safe_join``; symlinks are refused and the
size is capped.

Entities are what the linter's entity-binding rule checks for: *which* input is
at risk (``sources``) and *which* operation it reaches (``sinks``). They come
from a small, explainable heuristic, not a taint engine: a source is a
parameter of the enclosing function or a local assigned from ``request``,
``input()``, ``sys.argv`` or ``os.environ``; a sink is a call on the finding's
lines that a source flows into (or, if none does, any non-trivial call there).
"""

from __future__ import annotations

import ast
import builtins
import io
import re
import textwrap
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from app.core.config import get_settings
from app.core.paths import PathTraversalError, safe_join
from app.core.redaction import redact
from app.intelligence.fingerprint import normalise_snippet
from app.mapping.mapper import canonical_cwe, owasp_label

_BUILTINS = frozenset(dir(builtins))
# Builtins that are themselves dangerous operations, so they count as sinks.
_DANGEROUS_BUILTINS = frozenset({"open", "eval", "exec", "compile", "__import__"})
_ENV_ROOTS = {("os", "environ"), ("os", "getenv"), ("sys", "argv")}


class ContextError(ValueError):
    """Context cannot be extracted safely or faithfully -- no prompt may be built."""


class FindingLike(Protocol):
    """Satisfied by both ``NormalizedFinding`` and the persisted ``Finding`` row."""

    tool: str
    rule_id: str
    cwe: str | None
    owasp: str | None
    severity: str
    message: str
    file_path: str
    start_line: int | None
    end_line: int | None
    snippet: str
    package: str | None
    package_version: str | None
    cve_ids: list[str]
    fix_versions: list[str]


@dataclass(frozen=True)
class Source:
    name: str
    origin: str          # human-readable: "the HTTP request (`request.args`)"


@dataclass(frozen=True)
class FindingContext:
    tool: str
    rule_id: str
    cwe: str | None
    owasp: str | None              # full label, e.g. "A03:2021 Injection"
    severity: str
    message: str                   # redacted, single line
    file_path: str
    start_line: int
    end_line: int
    window_start: int
    window_end: int
    window_kind: str               # function | lines | main-block | statement | dependency
    symbol: str | None
    code: str                      # dedented, comment/docstring-free, redacted
    indent: str                    # the window's original indentation (lab-mode re-indent)
    sources: tuple[Source, ...] = ()
    sinks: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    constants: tuple[str, ...] = ()
    package: str | None = None
    package_version: str | None = None
    vulns: tuple[str, ...] = ()
    fixed_version: str | None = None
    snippet_verified: bool | None = None   # None: the scanner gave no snippet to compare

    @property
    def lines_label(self) -> str:
        return f"{self.window_start}-{self.window_end}" if self.window_end != self.window_start \
            else str(self.window_start)

    @property
    def entities(self) -> tuple[str, ...]:
        """Every name the linter accepts as binding the prompt to this finding."""
        names = [s.name for s in self.sources] + list(self.sinks) + list(self.targets)
        if self.package:
            names.append(self.package)
        return tuple(dict.fromkeys(names))

    def slots(self) -> dict[str, str]:
        """Values for the guidance templates (app/mapping/data/cwe_guidance.yaml)."""
        first_source = self.sources[0] if self.sources else None
        return {
            "source": first_source.name if first_source else "",
            "origin": first_source.origin if first_source else "",
            "sink": self.sinks[0] if self.sinks else "",
            "target": self.targets[0] if self.targets else "",
            "base": self.constants[0] if self.constants else "",
            "symbol": self.symbol or "",
            "package": self.package or "",
            "version": self.package_version or "",
            "fixed": self.fixed_version or "",
            "vulns": ", ".join(self.vulns),
            "cwe": self.cwe or "",
        }


# ---- reading --------------------------------------------------------------


def read_source(root: Path, rel_path: str) -> str:
    try:
        path = safe_join(root, *Path(rel_path).parts)
    except PathTraversalError as exc:
        raise ContextError(str(exc)) from exc
    if path.is_symlink() or not path.is_file():
        raise ContextError(f"not a regular file: {rel_path}")
    if path.stat().st_size > get_settings().max_context_file_bytes:
        raise ContextError(f"file too large to extract context from: {rel_path}")
    return path.read_text(encoding="utf-8", errors="replace")


# ---- python structure ---------------------------------------------------------


def _span(node: ast.AST) -> tuple[int, int]:
    start = node.lineno
    for deco in getattr(node, "decorator_list", []):
        start = min(start, deco.lineno)
    return start, node.end_lineno or node.lineno


def _enclosing_function(tree: ast.AST, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start, end = _span(node)
            if start <= line <= end and (best is None or start >= _span(best)[0]):
                best = node
    return best


def _main_block(tree: ast.Module, line: int) -> ast.If | None:
    for node in tree.body:
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"
                and node.lineno <= line <= (node.end_lineno or node.lineno)):
            return node
    return None


def _statement(tree: ast.Module, line: int) -> ast.stmt | None:
    body: list[ast.stmt] = tree.body
    while True:
        hit = next((n for n in body if n.lineno <= line <= (n.end_lineno or n.lineno)), None)
        if isinstance(hit, ast.ClassDef):
            body = hit.body
            continue
        return hit


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _source_origin(expr: ast.AST) -> str | None:
    for node in ast.walk(expr):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input":
            return "user input (`input()`)"
        if isinstance(node, ast.Attribute):
            dotted = _dotted(node)
            if not dotted:
                continue
            parts = dotted.split(".")
            if parts[0] == "request" and len(parts) >= 2:
                return f"the HTTP request (`{'.'.join(parts[:2])}`)"
            if tuple(parts[:2]) in _ENV_ROOTS:
                return f"outside the program (`{'.'.join(parts[:2])}`)"
    return None


def _names_on(scope: ast.AST, start: int, end: int) -> list[str]:
    seen: dict[str, None] = {}
    for node in ast.walk(scope):
        if isinstance(node, ast.Name) and start <= node.lineno <= end:
            seen.setdefault(node.id, None)
    return list(seen)


def _entities(tree: ast.Module, func: ast.AST | None, start: int, end: int):
    scope = func or tree
    tainted: dict[str, str] = {}
    if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = func.args
        for a in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
            if a is not None and a.arg not in {"self", "cls"}:
                tainted[a.arg] = f"the caller of `{func.name}` (parameter `{a.arg}`)"
    for node in ast.walk(scope):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            origin = _source_origin(node.value)
            if origin:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            tainted[n.id] = origin

    names = _names_on(scope, start, end)
    sources = tuple(Source(n, tainted[n]) for n in names if n in tainted)

    flowing: list[str] = []
    other: list[str] = []
    for node in ast.walk(scope):
        if not (isinstance(node, ast.Call) and start <= node.lineno <= end):
            continue
        name = _dotted(node.func)
        if not name:
            continue
        root = name.split(".")[0]
        if root in tainted or root == "request" or (name in _BUILTINS and name not in _DANGEROUS_BUILTINS):
            continue
        args = [*node.args, *(k.value for k in node.keywords)]
        flows = any(isinstance(n, ast.Name) and n.id in tainted for a in args for n in ast.walk(a))
        (flowing if flows else other).append(name)
    sinks = tuple(dict.fromkeys(flowing or other))

    # At module level the assigned or imported name *is* the flagged thing
    # (API_TOKEN, `import pickle`). Inside a function, a local assigned on the
    # finding's line (`output = ...`) is not what is at risk, so it is not an entity.
    targets: list[str] = []
    for node in ast.walk(scope) if func is None else ():
        if isinstance(node, ast.Assign) and start <= node.lineno <= end:
            targets += [t.id for t in node.targets if isinstance(t, ast.Name)]
        if isinstance(node, (ast.Import, ast.ImportFrom)) and start <= node.lineno <= end:
            targets += [(a.asname or a.name).split(".")[0] for a in node.names]
    constants = tuple(n for n in names if n.isupper() and n not in tainted and n not in targets)
    return sources, sinks, tuple(dict.fromkeys(targets)), constants


# ---- stripping --------------------------------------------------------------


def _comment_columns(text: str) -> dict[int, int]:
    cols: dict[int, int] = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                cols[tok.start[0]] = tok.start[1]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return cols


def _docstring_lines(tree: ast.Module | None) -> set[int]:
    lines: set[int] = set()
    if tree is None:
        return lines
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            is_doc = (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                      and isinstance(first.value.value, str))
            # A body that is *only* a docstring keeps it, or the code would not parse.
            if is_doc and (len(node.body) > 1 or isinstance(node, ast.Module)):
                lines.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
    return lines


def _window_code(lines: list[str], start: int, end: int, tree: ast.Module | None,
                 comments: dict[int, int]) -> tuple[str, str]:
    docs = _docstring_lines(tree)
    kept: list[str] = []
    for number in range(start, end + 1):
        if number in docs:
            continue
        line = lines[number - 1]
        if number in comments:
            line = line[:comments[number]].rstrip()
            if not line.strip():
                continue
        elif tree is None and line.lstrip().startswith("#"):
            continue
        kept.append(line.rstrip())
    while kept and not kept[-1].strip():
        kept.pop()
    nonblank = [line for line in kept if line.strip()]
    indent = ""
    if nonblank:
        shallowest = min(nonblank, key=lambda line: len(line) - len(line.lstrip()))
        indent = shallowest[:len(shallowest) - len(shallowest.lstrip())]
    return redact(textwrap.dedent("\n".join(kept))), indent


# ---- dependency metadata ----------------------------------------------------


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v)[:4])


def _fixed_version(current: str | None, candidates: list[str]) -> str | None:
    if not candidates:
        return None
    ordered = sorted(candidates, key=_version_key)
    if current:
        newer = [v for v in ordered if _version_key(v) > _version_key(current)]
        if newer:
            return newer[0]
    return ordered[0]


def _dependency_line(lines: list[str], package: str) -> int | None:
    pattern = re.compile(rf"^\s*{re.escape(package)}\s*([=<>~!]|$)", re.IGNORECASE)
    return next((i for i, line in enumerate(lines, start=1) if pattern.match(line)), None)


# ---- entry point ------------------------------------------------------------


def extract_context(finding: FindingLike, source_root: Path) -> FindingContext:
    """Build the minimal context for ``finding`` from the code under ``source_root``."""
    settings = get_settings()
    text = read_source(source_root, finding.file_path)
    lines = text.splitlines()
    start = finding.start_line
    if start is None and finding.package:
        start = _dependency_line(lines, finding.package)
    if start is None:
        raise ContextError("finding has no line to extract context for")
    end = max(finding.end_line or start, start)
    if start < 1 or end > len(lines):
        raise ContextError("finding lies outside the file -- the source differs from the scanned version")

    radius, max_lines = settings.context_radius, settings.max_context_lines
    tree: ast.Module | None = None
    if finding.file_path.endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None

    func = main = None
    symbol: str | None = finding.package
    if finding.package or tree is None:
        win = (start, end)
        kind = "dependency" if finding.package else "lines"
    elif (func := _enclosing_function(tree, start)) is not None:
        fs, fe = _span(func)
        symbol = func.name
        if fe - fs + 1 <= max_lines:
            win, kind = (fs, fe), "function"
        else:
            win, kind = (max(fs, start - radius), min(fe, end + radius)), "lines"
    elif (main := _main_block(tree, start)) is not None:
        ms, me = _span(main)
        symbol = "__main__"
        win = (ms, me) if me - ms + 1 <= max_lines else (max(ms, start - radius), min(me, end + radius))
        kind = "main-block"
    else:
        stmt = _statement(tree, start)
        ss, se = _span(stmt) if stmt is not None else (start, end)
        win = (ss, se) if se - ss + 1 <= max_lines else (max(ss, start - radius), min(se, end + radius))
        kind = "statement"

    code, indent = _window_code(lines, win[0], win[1], tree, _comment_columns(text) if tree else {})
    if not code.strip():
        raise ContextError("no code left in the context window after stripping comments")

    sources: tuple[Source, ...] = ()
    sinks: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    constants: tuple[str, ...] = ()
    if tree is not None and not finding.package:
        sources, sinks, targets, constants = _entities(tree, func, start, end)
        if kind == "statement" and targets and symbol is None:
            symbol = targets[0]

    snippet = normalise_snippet(finding.snippet or "").lower()
    original = normalise_snippet(redact("\n".join(lines[win[0] - 1:win[1]]))).lower()
    verified = (snippet in original) if snippet else None

    cwe = canonical_cwe(finding.cwe)
    vulns = tuple(finding.cve_ids or []) or ((finding.rule_id,) if finding.package else ())
    return FindingContext(
        tool=finding.tool, rule_id=finding.rule_id, cwe=cwe,
        owasp=owasp_label(finding.owasp) or finding.owasp, severity=finding.severity,
        message=" ".join(redact(finding.message).split())[:500],
        file_path=finding.file_path, start_line=start, end_line=end,
        window_start=win[0], window_end=win[1], window_kind=kind, symbol=symbol,
        code=code, indent=indent, sources=sources, sinks=sinks, targets=targets, constants=constants,
        package=finding.package, package_version=finding.package_version, vulns=vulns,
        fixed_version=_fixed_version(finding.package_version, list(finding.fix_versions or [])),
        snippet_verified=verified,
    )
