"""Symbol facts: the structural evidence gate 3a compares (no execution, no stored code)."""

from __future__ import annotations

import ast
import textwrap

import pytest

from app.verification.symbols import (ASSIGNMENT, DEPENDENCY, FILE, FILE_MISSING, FILE_SYMBOL, FUNCTION,
                                      MAIN_BLOCK, MISSING, PRESENT, UNPARSEABLE, facts_for, is_trivial, locate,
                                      signature)

SOURCE = textwrap.dedent('''\
    """Module docstring."""
    import os
    from flask import Flask, request

    app = Flask(__name__)
    TOKEN = "x"


    @app.route("/user")
    def get_user(user_id, limit=10, *, verbose=False, **extra):
        """Docstring."""
        rows = query(user_id)
        return [r for r in rows if r]


    def query(q):
        return os.listdir(q)


    class Repo:
        def load(self, key):
            def inner(k):
                return key + k
            return inner(key)


    if __name__ == "__main__":
        app.run(debug=True)
''')


def _line(text: str, needle: str) -> int:
    return next(i for i, line in enumerate(text.splitlines(), start=1) if needle in line)


@pytest.mark.parametrize("needle, expected", [
    ("rows = query(user_id)", ("get_user", FUNCTION)),
    ('@app.route("/user")', ("get_user", FUNCTION)),          # decorators belong to the function
    ("return key + k", ("Repo.load.inner", FUNCTION)),        # innermost, qualified
    ("return inner(key)", ("Repo.load", FUNCTION)),
    ("app.run(debug=True)", ("__main__", MAIN_BLOCK)),
    ('TOKEN = "x"', ("TOKEN", ASSIGNMENT)),
    ("import os", (FILE_SYMBOL, FILE)),
])
def test_locate_names_the_symbol_a_finding_is_about(needle: str, expected: tuple[str, str]) -> None:
    assert locate(ast.parse(SOURCE), _line(SOURCE, needle)) == expected


def test_locate_dependency_and_unparseable() -> None:
    assert locate(None, 6, package="PyYAML") == ("pyyaml", DEPENDENCY)
    assert locate(None, 3) == (FILE_SYMBOL, FILE)


def test_function_facts() -> None:
    f = facts_for("app.py", "get_user", FUNCTION, SOURCE)
    assert f.state == PRESENT
    assert f.signature == "(user_id, limit=, *, verbose=, **extra)"
    assert f.decorators == ("app.route('/user')",)       # ast.unparse: formatting-independent
    assert not f.body_trivial
    assert f.undefined_names == ()
    assert f.contains(_line(SOURCE, "rows = query")) and not f.contains(_line(SOURCE, "def query"))


def test_signature_ignores_annotations_and_default_values() -> None:
    a = ast.parse("def f(a, b=1, *args, c, d=2, **kw): pass").body[0].args
    b = ast.parse("def f(a: int, b: int = 99, *args: str, c: int, d=None, **kw) -> int: pass").body[0].args
    assert signature(a) == signature(b) == "(a, b=, *args, c, d=, **kw)"
    assert signature(ast.parse("def f(a, /, b): pass").body[0].args) == "(a, /, b)"


@pytest.mark.parametrize("body, trivial", [
    ("pass", True),
    ("...", True),
    ('"""only a docstring"""', True),
    ("return", True),
    ("return None", True),
    ('return "ok"', True),
    ("raise NotImplementedError", True),
    ("x = 1\nreturn x", False),
    ("return compute(x)", False),
    ('return {"rows": rows}', False),
])
def test_stub_detection(body: str, trivial: bool) -> None:
    func = ast.parse("def f(x):\n" + textwrap.indent(body, "    ")).body[0]
    assert is_trivial(func.body) is trivial


def test_new_undefined_name_is_detected() -> None:
    broken = SOURCE.replace("rows = query(user_id)", "rows = sanitize_and_query(user_id)")
    assert facts_for("app.py", "get_user", FUNCTION, broken).undefined_names == ("sanitize_and_query",)


def test_names_from_any_scope_count_as_defined() -> None:
    src = textwrap.dedent('''\
        import shlex as sh
        try:
            from json import loads
        except ImportError:
            loads = None
        LIMIT = 3

        def f(a):
            global COUNTER
            COUNTER = 1
            for i, (k, v) in enumerate(a.items()):
                with open(k) as fh:
                    data = [y for y in fh if y]
            try:
                pass
            except ValueError as err:
                print(err)
            return sh.quote(v), loads, LIMIT, data, i, __name__, len

        def g():
            return COUNTER
    ''')
    assert facts_for("m.py", "f", FUNCTION, src).undefined_names == ()
    assert facts_for("m.py", "g", FUNCTION, src).undefined_names == ()


def test_star_import_is_flagged_so_undefined_names_are_not_trusted() -> None:
    src = "from os.path import *\n\ndef f(p):\n    return join(p, 'x')\n"
    facts = facts_for("m.py", "f", FUNCTION, src)
    assert facts.star_import and facts.undefined_names == ("join",)


def test_states() -> None:
    assert facts_for("app.py", "get_user", FUNCTION, None).state == FILE_MISSING
    assert facts_for("app.py", "get_user", FUNCTION, "def broken(:\n").state == UNPARSEABLE
    assert facts_for("app.py", "get_user", FUNCTION, "def other(): pass\n").state == MISSING
    main = facts_for("app.py", "__main__", MAIN_BLOCK, SOURCE)
    assert main.state == PRESENT and not main.body_trivial
    assert facts_for("app.py", "TOKEN", ASSIGNMENT, SOURCE.replace('TOKEN = "x"', "import os as TOKEN")).state \
        == PRESENT                                        # still bound, by another kind of statement
    assert facts_for("app.py", "TOKEN", ASSIGNMENT, SOURCE.replace('TOKEN = "x"', "")).state == MISSING


def test_dependency_and_non_python_files() -> None:
    reqs = "# pinned\nflask==3.1.3\nPyYAML==5.4.1\n"
    dep = facts_for("requirements.txt", "pyyaml", DEPENDENCY, reqs)
    assert dep.state == PRESENT and dep.span_start == 3
    assert facts_for("requirements.txt", "pyyaml", DEPENDENCY, "flask==3.1.3\n").state == MISSING
    other = facts_for(".env", FILE_SYMBOL, FILE, "A=1\nB=2\n")
    assert other.state == PRESENT and (other.span_start, other.span_end) == (1, 2)


def test_decorator_text_is_redacted() -> None:
    src = 'import auth\n\n@auth.require(token="ghp_' + "a" * 36 + '")\ndef f():\n    return 1\n'
    (decorator,) = facts_for("m.py", "f", FUNCTION, src).decorators
    assert "ghp_" + "a" * 36 not in decorator
