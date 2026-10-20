"""Scan-time symbol snapshots on the real fixture, from the 24 recorded real-scanner findings."""

from __future__ import annotations

import shutil
from pathlib import Path

from app.verification.snapshots import capture
from app.verification.symbols import FILE_MISSING, MISSING, PRESENT, UNPARSEABLE
from tests._ai_support import FIXTURE, recorded_findings


def _by_symbol(facts):  # noqa: ANN001, ANN202
    return {(f.file_path, f.symbol): f for f in facts}


def test_every_seeded_weakness_gets_a_snapshot() -> None:
    snaps = _by_symbol(capture(FIXTURE, recorded_findings()))
    expected = {
        ("app.py", "get_user"): "function", ("app.py", "ping_host"): "function", ("app.py", "greet"): "function",
        ("app.py", "download_file"): "function", ("app.py", "restore_session"): "function",
        ("app.py", "__main__"): "main-block", ("app.py", "<file>"): "file",         # B403/B404 import advisories
        ("config.py", "API_TOKEN"): "assignment",
        ("crypto_utils.py", "hash_password"): "function", ("crypto_utils.py", "make_reset_token"): "function",
        ("requirements.txt", "pyyaml"): "dependency",
    }
    assert {k: v.kind for k, v in snaps.items()} == expected
    assert all(s.state == PRESENT for s in snaps.values())
    assert snaps[("crypto_utils.py", "hash_password")].signature == "(password)"
    assert snaps[("app.py", "restore_session")].decorators == ("app.route('/session', methods=['POST'])",)


def test_carried_symbols_record_what_became_of_them(tmp_path: Path) -> None:
    code = tmp_path / "code"
    shutil.copytree(FIXTURE, code)
    (code / "crypto_utils.py").unlink()
    (code / "config.py").write_text("def broken(:\n", encoding="utf-8")
    app = code / "app.py"
    app.write_text(app.read_text(encoding="utf-8").replace("def greet():", "def greeting():"), encoding="utf-8")
    carried = [("crypto_utils.py", "hash_password", "function"), ("config.py", "API_TOKEN", "assignment"),
               ("app.py", "greet", "function")]
    snaps = _by_symbol(capture(code, [], carried))
    assert snaps[("crypto_utils.py", "hash_password")].state == FILE_MISSING
    assert snaps[("config.py", "API_TOKEN")].state == UNPARSEABLE
    assert snaps[("app.py", "greet")].state == MISSING


def test_paths_outside_the_tree_are_never_read(tmp_path: Path) -> None:
    (tmp_path / "secret.py").write_text("def f():\n    pass\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (snap,) = capture(root, [], [("../secret.py", "f", "function")])
    assert snap.state == UNPARSEABLE            # refused, not read
