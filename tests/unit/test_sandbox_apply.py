"""Lab-mode apply: a whole-window text splice into a scratch copy, refused rather than guessed."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.ai.context import FindingContext, extract_context
from app.ai.output_schema import FixProposal
from app.sandbox.apply import ApplyError, apply_proposal
from tests._ai_support import finding


def _ctx(path: str, start: int, end: int, indent: str = "") -> FindingContext:
    return FindingContext(tool="bandit", rule_id="B1", cwe="CWE-89", owasp=None, severity="HIGH", message="m",
                          file_path=path, start_line=start, end_line=end, window_start=start, window_end=end,
                          window_kind="function", symbol="f", code="", indent=indent)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return path


MODULE = '"""Doc."""\nfrom __future__ import annotations\n\nimport os\n\n\nclass Repo:\n    def load(self, key):\n' \
         '        return os.system(key)\n\n\ndef other():\n    return 1\n'


def test_window_is_replaced_and_reindented(tmp_path: Path) -> None:
    path = _write(tmp_path, "m.py", MODULE)
    code = "def load(self, key):\n    import shlex\n    return os.listdir(shlex.quote(key))"
    patch = apply_proposal(tmp_path, _ctx("m.py", 8, 9, indent="    "), FixProposal(code=code))
    text = path.read_text(encoding="utf-8")
    assert "    def load(self, key):\n        import shlex\n        return os.listdir(shlex.quote(key))\n" in text
    assert "os.system" not in text and "def other():\n    return 1\n" in text
    assert (patch.window, patch.new_lines) == ((8, 9), 3)


def test_imports_go_after_docstring_and_future_imports_once(tmp_path: Path) -> None:
    path = _write(tmp_path, "m.py", MODULE)
    proposal = FixProposal(code="def load(self, key):\n    return shlex.quote(key)",
                           imports=["import shlex", "import os", "import shlex"])
    patch = apply_proposal(tmp_path, _ctx("m.py", 8, 9, indent="    "), proposal)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[:4] == ['"""Doc."""', "from __future__ import annotations", "import shlex", ""]
    assert patch.imports_added == ("import shlex",)            # `import os` already present; duplicates dropped


def test_fixture_window_from_real_context(tmp_path: Path) -> None:
    root = tmp_path / "code"
    _write(root, "app.py", (Path(__file__).resolve().parents[2] / "fixtures" / "flask_vuln_app" / "app.py")
           .read_text(encoding="utf-8"))
    ctx = extract_context(finding("B608"), root)
    code = ctx.code.replace("'%s'\" % user_id)", "?\", (user_id,))")
    apply_proposal(root, ctx, FixProposal(code=code))
    text = (root / "app.py").read_text(encoding="utf-8")
    assert 'WHERE id = ?", (user_id,))' in text and "% user_id" not in text
    assert '@app.route("/user")\ndef get_user():' in text           # the decorator is part of the window


def test_line_endings_are_preserved(tmp_path: Path) -> None:
    path = _write(tmp_path, "m.py", MODULE.replace("\n", "\r\n"))
    apply_proposal(tmp_path, _ctx("m.py", 12, 13), FixProposal(code="def other():\n    return 2"))
    raw = path.read_bytes()
    assert b"return 2\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b"")


def test_dependency_window(tmp_path: Path) -> None:
    path = _write(tmp_path, "requirements.txt", "flask==3.1.3\nPyYAML==5.3\n")
    apply_proposal(tmp_path, _ctx("requirements.txt", 2, 2), FixProposal(code="PyYAML==6.0.3"))
    assert path.read_text(encoding="utf-8") == "flask==3.1.3\nPyYAML==6.0.3\n"


@pytest.mark.parametrize("ctx, proposal, message", [
    (_ctx("requirements.txt", 1, 1), FixProposal(code="x==1", imports=["import os"]), "not Python"),
    (_ctx("m.py", 40, 41), FixProposal(code="x = 1"), "outside the file"),
    (_ctx("../outside.py", 1, 1), FixProposal(code="x = 1"), "escapes"),
    (_ctx("missing.py", 1, 1), FixProposal(code="x = 1"), "not a regular file"),
])
def test_refusals(tmp_path: Path, ctx: FindingContext, proposal: FixProposal, message: str) -> None:
    _write(tmp_path, "m.py", MODULE)
    _write(tmp_path, "requirements.txt", "flask==3.1.3\n")
    _write(tmp_path.parent, "outside.py", "x = 0\n")
    with pytest.raises(ApplyError, match=message):
        apply_proposal(tmp_path, ctx, proposal)
    assert (tmp_path.parent / "outside.py").read_text(encoding="utf-8") == "x = 0\n"


def test_symlinked_target_is_refused(tmp_path: Path) -> None:
    real = _write(tmp_path, "real.py", "x = 0\n")
    try:
        os.symlink(real, tmp_path / "link.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need extra privileges on this platform")
    with pytest.raises(ApplyError):
        apply_proposal(tmp_path, _ctx("link.py", 1, 1), FixProposal(code="x = 1"))
    assert real.read_text(encoding="utf-8") == "x = 0\n"
