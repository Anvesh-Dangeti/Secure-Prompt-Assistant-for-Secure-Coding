"""Path containment and guaranteed scratch cleanup."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from app.core.paths import PathTraversalError, is_within, repo_relative, safe_join
from app.core.scratch import remove_tree, scratch_dir, scratch_root


def test_is_within_basic(tmp_path: Path) -> None:
    assert is_within(tmp_path / "a" / "b", tmp_path)
    assert is_within(tmp_path, tmp_path)
    assert not is_within(tmp_path / ".." / "sibling", tmp_path)
    assert not is_within(tmp_path.parent, tmp_path)


def test_prefix_sibling_is_not_within(tmp_path: Path) -> None:
    # "/tmp/scratch-evil" must not count as inside "/tmp/scratch".
    base = tmp_path / "scratch"
    assert not is_within(tmp_path / "scratch-evil" / "x", base)


@pytest.mark.parametrize("part", ["../escape.txt", "a/../../escape.txt", "/etc/passwd", "C:/Windows/win.ini"])
def test_safe_join_rejects_traversal(tmp_path: Path, part: str) -> None:
    with pytest.raises(PathTraversalError):
        safe_join(tmp_path, part)


def test_safe_join_allows_nested(tmp_path: Path) -> None:
    assert safe_join(tmp_path, "a", "b.txt") == tmp_path / "a" / "b.txt"


def test_repo_relative_normalises_and_rejects_escape(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    assert repo_relative("pkg\\mod.py", tmp_path) == "pkg/mod.py"
    assert repo_relative(tmp_path / "pkg" / "mod.py", tmp_path) == "pkg/mod.py"
    assert repo_relative("../outside.py", tmp_path) is None


def test_scratch_dir_is_removed_on_success() -> None:
    with scratch_dir() as path:
        (path / "f.txt").write_text("x")
    assert not path.exists()


def test_scratch_dir_is_removed_on_exception() -> None:
    with pytest.raises(RuntimeError), scratch_dir() as path:
        (path / "f.txt").write_text("x")
        raise RuntimeError("scan crashed")
    assert not path.exists()


def test_read_only_files_are_removed() -> None:
    # git object files are read-only on Windows; cleanup must still succeed.
    with scratch_dir() as path:
        target = path / "objects" / "pack"
        target.mkdir(parents=True)
        ro = target / "pack-1.idx"
        ro.write_bytes(b"\x00" * 16)
        os.chmod(ro, stat.S_IREAD)
    assert not path.exists()


def test_remove_tree_refuses_outside_scratch(tmp_path: Path) -> None:
    precious = tmp_path / "precious"
    precious.mkdir()
    with pytest.raises(PermissionError):
        remove_tree(precious)
    assert precious.exists()


def test_remove_tree_refuses_the_scratch_root_itself() -> None:
    with pytest.raises(PermissionError):
        remove_tree(scratch_root())
