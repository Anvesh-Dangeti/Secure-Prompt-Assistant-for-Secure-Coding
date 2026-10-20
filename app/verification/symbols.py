"""Structural facts about one flagged symbol -- what gate 3a compares before and after a fix.

A scan deletes its copy of the code, so verification cannot diff source. It
compares *facts* instead, recorded at scan time for every symbol that has (or
had) a finding:

* a function -- still defined under the same qualified name, with the same
  parameters, at least the same decorators, a body that is more than a stub,
  and no name in it that nothing defines?
* a module-level name (``API_TOKEN``) -- still bound?
* the ``if __name__ == "__main__":`` block -- still there, and not a stub?
* a dependency -- still listed in its requirements file?

Each is a cheap AST question with an explainable answer. Together they catch
the fake fixes Paper 3 section 7.4 describes (deleting the function, emptying
it, calling something that does not exist) without executing anything.
"""

from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass, replace

# Shared with the context extractor, so "the lines of a symbol" and "the line of
# a dependency" mean the same thing in the prompt and in verification.
from app.ai.context import _dependency_line, _span
from app.core.redaction import redact

PRESENT, MISSING, FILE_MISSING, UNPARSEABLE = "PRESENT", "MISSING", "FILE_MISSING", "UNPARSEABLE"
FUNCTION, ASSIGNMENT, MAIN_BLOCK, DEPENDENCY, FILE = "function", "assignment", "main-block", "dependency", "file"
FILE_SYMBOL = "<file>"
MAIN_SYMBOL = "__main__"

_MODULE_DUNDERS = frozenset({"__name__", "__file__", "__doc__", "__spec__", "__loader__", "__package__",
                             "__builtins__", "__path__", "__annotations__"})
_ALWAYS_DEFINED = frozenset(dir(builtins)) | _MODULE_DUNDERS
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


@dataclass(frozen=True)
class SymbolFacts:
    file_path: str
    symbol: str
    kind: str
    state: str
    span_start: int | None = None
    span_end: int | None = None
    signature: str | None = None
    decorators: tuple[str, ...] = ()
    body_trivial: bool = False
    undefined_names: tuple[str, ...] = ()
    star_import: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return self.file_path, self.symbol

    @property
    def label(self) -> str:
        if self.kind == FILE:
            return self.file_path
        return f"`{self.symbol}` ({self.file_path})"

    def contains(self, line: int | None) -> bool:
        return (line is not None and self.span_start is not None and self.span_end is not None
                and self.span_start <= line <= self.span_end)


# ---- finding the symbol -------------------------------------------------------


def functions(tree: ast.Module) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """Every function with its qualified name (``Cls.method``, ``outer.inner``), in source order."""
    out: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _FUNCS):
                out.append((prefix + child.name, child))
                visit(child, f"{prefix}{child.name}.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            else:
                visit(child, prefix)

    visit(tree, "")
    return out


def _main_block(tree: ast.Module) -> ast.If | None:
    for node in tree.body:
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"):
            return node
    return None


def _bound_by(node: ast.AST, names: set[str]) -> None:
    """Add the names one AST node binds (without descending into it)."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        names.add(node.id)
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        names.update((a.asname or a.name).split(".")[0] for a in node.names if a.name != "*")
    elif isinstance(node, ast.ExceptHandler) and node.name:
        names.add(node.name)
    elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
        names.add(node.name)
    elif isinstance(node, ast.MatchMapping) and node.rest:
        names.add(node.rest)


def _statement_names(stmt: ast.stmt) -> set[str]:
    """Names a module-level statement binds, looking through if/try/with/for but not into defs."""
    names: set[str] = set()
    if isinstance(stmt, (*_FUNCS, ast.ClassDef)):
        return {stmt.name}
    stack: list[ast.AST] = [stmt]
    while stack:
        node = stack.pop()
        _bound_by(node, names)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (*_FUNCS, ast.ClassDef)):
                names.add(child.name)
            elif not isinstance(child, ast.Lambda):
                stack.append(child)
    return names


def _assigned_names(stmt: ast.stmt) -> list[str]:
    targets: list[ast.expr] = []
    if isinstance(stmt, ast.Assign):
        targets = stmt.targets
    elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
        targets = [stmt.target]
    return [n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)]


def locate(tree: ast.Module | None, line: int | None, package: str | None = None) -> tuple[str, str]:
    """``(symbol, kind)`` of what a finding at ``line`` is about."""
    if package:
        return package.lower(), DEPENDENCY
    if tree is None or line is None:
        return FILE_SYMBOL, FILE
    best: tuple[str, int] | None = None
    for name, node in functions(tree):
        start, end = _span(node)
        if start <= line <= end and (best is None or start >= best[1]):
            best = (name, start)
    if best is not None:
        return best[0], FUNCTION
    main = _main_block(tree)
    if main is not None and main.lineno <= line <= (main.end_lineno or main.lineno):
        return MAIN_SYMBOL, MAIN_BLOCK
    for stmt in tree.body:
        if stmt.lineno <= line <= (stmt.end_lineno or stmt.lineno):
            names = _assigned_names(stmt)
            if names:
                return names[0], ASSIGNMENT
            break
    return FILE_SYMBOL, FILE


# ---- facts --------------------------------------------------------------------


def signature(args: ast.arguments) -> str:
    """Parameter names, kinds and which have defaults -- not annotations, not default values.

    Adding type hints is not a behaviour change; dropping or renaming a
    parameter breaks every caller.
    """
    positional = [*args.posonlyargs, *args.args]
    first_default = len(positional) - len(args.defaults)
    parts: list[str] = []
    for i, a in enumerate(positional):
        parts.append(a.arg + ("=" if i >= first_default else ""))
        if args.posonlyargs and i == len(args.posonlyargs) - 1:
            parts.append("/")
    if args.vararg:
        parts.append("*" + args.vararg.arg)
    elif args.kwonlyargs:
        parts.append("*")
    parts += [a.arg + ("=" if d is not None else "") for a, d in zip(args.kwonlyargs, args.kw_defaults)]
    if args.kwarg:
        parts.append("**" + args.kwarg.arg)
    return "(" + ", ".join(parts) + ")"


def _is_docstring(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)


def is_trivial(body: list[ast.stmt]) -> bool:
    """A stub: nothing left but ``pass``, ``...``, a bare or constant ``return``, or a ``raise``."""
    stmts = body[1:] if body and _is_docstring(body[0]) else body
    if all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
           for s in stmts):
        return True
    if len(stmts) == 1:
        s = stmts[0]
        if isinstance(s, ast.Raise):
            return True
        if isinstance(s, ast.Return) and (s.value is None or isinstance(s.value, ast.Constant)):
            return True
    return False


def _module_bindings(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for stmt in tree.body:
        names |= _statement_names(stmt)
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):    # `global x` in a function binds x at module level
            names.update(node.names)
    return names


def _local_bindings(func: ast.AST) -> set[str]:
    """Everything bound anywhere inside ``func`` -- deliberately generous (nested scopes included).

    Over-approximating what is defined can only hide an undefined name, never
    invent one, so gate 3a cannot reject a fix for a name that does exist.
    """
    names: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (*_FUNCS, ast.ClassDef)) and node is not func:
            names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
        else:
            _bound_by(node, names)
    return names


def undefined_names(tree: ast.Module, func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names ``func`` reads that no enclosing scope, module binding or builtin defines."""
    known = _module_bindings(tree) | _local_bindings(func) | _ALWAYS_DEFINED
    for _, outer in functions(tree):
        if outer is not func and any(n is func for n in ast.walk(outer)):
            known |= _local_bindings(outer)
    loads = {n.id for n in ast.walk(func) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    return loads - known


def _find_function(tree: ast.Module, qualname: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    found = None
    for name, node in functions(tree):
        if name == qualname:
            found = node            # the last definition is the one Python keeps
    return found


def _find_binding(tree: ast.Module, name: str) -> ast.stmt | None:
    found = None
    for stmt in tree.body:
        if name in _statement_names(stmt):
            found = stmt
    return found


def parse(text: str | None) -> ast.Module | None:
    if text is None:
        return None
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def facts_for(file_path: str, symbol: str, kind: str, text: str | None,
              tree: ast.Module | None = None) -> SymbolFacts:
    """Facts about ``symbol`` in ``text``. ``text`` is ``None`` when the file does not exist."""
    base = SymbolFacts(file_path, symbol, kind, FILE_MISSING)
    if text is None:
        return base
    lines = text.splitlines()
    whole = replace(base, state=PRESENT, span_start=1, span_end=max(len(lines), 1))
    if kind == DEPENDENCY:
        line = _dependency_line(lines, symbol)
        return replace(base, state=PRESENT if line else MISSING, span_start=line, span_end=line)
    if not file_path.endswith(".py"):
        return whole
    tree = tree or parse(text)
    if tree is None:
        return replace(base, state=UNPARSEABLE)
    star = any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names) for n in ast.walk(tree))
    whole, base = replace(whole, star_import=star), replace(base, state=MISSING, star_import=star)
    if kind == FILE:
        return whole
    if kind == FUNCTION:
        func = _find_function(tree, symbol)
        if func is None:
            return base
        start, end = _span(func)
        return replace(base, state=PRESENT, span_start=start, span_end=end, signature=signature(func.args),
                       decorators=tuple(redact(ast.unparse(d)) for d in func.decorator_list),
                       body_trivial=is_trivial(func.body), undefined_names=tuple(sorted(undefined_names(tree, func))))
    if kind == MAIN_BLOCK:
        main = _main_block(tree)
        if main is None:
            return base
        start, end = _span(main)
        return replace(base, state=PRESENT, span_start=start, span_end=end, body_trivial=is_trivial(main.body))
    if kind == ASSIGNMENT:
        stmt = _find_binding(tree, symbol)
        if stmt is None:
            return base
        return replace(base, state=PRESENT, span_start=stmt.lineno, span_end=stmt.end_lineno or stmt.lineno)
    return base
