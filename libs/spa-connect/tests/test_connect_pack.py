"""What leaves the machine: source in; caches, local secret files, links and ignored paths out; limits first."""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from spa_connect import pack as packing
from spa_connect.pack import PackError, is_ignored, pack


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _names(archive: Path) -> set[str]:
    with zipfile.ZipFile(archive) as zf:
        return set(zf.namelist())


def test_source_is_packed_and_noise_is_not(tmp_path: Path) -> None:
    root = _tree(tmp_path / "p", {
        "app.py": "x = 1\n", "pkg/util.py": "y = 2\n", "requirements.txt": "flask==3.0\n",
        ".env.example": "KEY=\n", ".env": "KEY=live\n", "config/prod.env": "KEY=live\n", ".env.local": "K=1\n",
        ".git/config": "[core]\n", ".venv/lib.py": "", "node_modules/x.js": "", "pkg/__pycache__/u.pyc": "",
        ".spa/connection.json": "{}",
    })
    packed = pack(root, tmp_path / "out.zip")
    assert _names(packed.archive) == {"app.py", "pkg/util.py", "requirements.txt", ".env.example"}
    assert sorted(packed.skipped_secrets) == [".env", ".env.local", "config/prod.env"]
    assert packed.files == 4


def test_spaignore_excludes_names_paths_and_folders(tmp_path: Path) -> None:
    root = _tree(tmp_path / "p", {
        ".spaignore": "# data is not code\ndata/\n*.csv\ndocs/build/*\n/notes.txt\n",
        "app.py": "", "data/big.bin": "", "sub/data/x.py": "", "a/b.csv": "", "docs/build/i.html": "",
        "docs/src.md": "", "notes.txt": "", "sub/notes.txt": "",
    })
    names = _names(pack(root, tmp_path / "out.zip").archive)
    assert names == {".spaignore", "app.py", "docs/src.md", "sub/notes.txt"}


def test_ignore_rules() -> None:
    assert is_ignored("a/b/c.csv", False, ["*.csv"])
    assert is_ignored("data", True, ["data/"]) and not is_ignored("data", False, ["data/"])
    assert is_ignored("x/data", True, ["data/"])
    assert not is_ignored("x/notes.txt", False, ["notes.txt/"])
    assert is_ignored("docs/build/a", False, ["docs/build/*"]) and not is_ignored("docs/src.md", False, ["docs/build/*"])


def _symlink(link: Path, target: Path, is_dir: bool) -> None:
    try:
        link.symlink_to(target, target_is_directory=is_dir)
    except (OSError, NotImplementedError):
        pytest.skip("this account may not create symbolic links")


def test_links_are_skipped_not_followed(tmp_path: Path) -> None:
    outside = _tree(tmp_path / "outside", {"secret.txt": "do not upload\n"})
    root = _tree(tmp_path / "p", {"app.py": ""})
    _symlink(root / "linked_dir", outside, True)
    _symlink(root / "linked.txt", outside / "secret.txt", False)
    packed = pack(root, tmp_path / "out.zip")
    assert _names(packed.archive) == {"app.py"}
    assert sorted(packed.skipped_links) == ["linked.txt", "linked_dir"]


def test_limits_fail_before_upload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _tree(tmp_path / "p", {"a.py": "x" * 2048, "b.py": "", "c.py": ""})
    monkeypatch.setattr(packing, "MAX_FILE_BYTES", 1024)
    with pytest.raises(PackError, match="a.py.*spaignore"):
        pack(root, tmp_path / "1.zip")
    monkeypatch.setattr(packing, "MAX_FILE_BYTES", 10**9)
    monkeypatch.setattr(packing, "MAX_FILES", 2)
    with pytest.raises(PackError, match="more than 2 files"):
        pack(root, tmp_path / "2.zip")
    monkeypatch.setattr(packing, "MAX_FILES", 10)
    monkeypatch.setattr(packing, "MAX_UPLOAD_BYTES", 10)
    with pytest.raises(PackError, match="packed project"):
        pack(root, tmp_path / "3.zip")


def test_too_deep_and_empty_projects_are_refused(tmp_path: Path) -> None:
    deep = "/".join(f"d{i}" for i in range(30)) + "/x.py"
    with pytest.raises(PackError, match="nested"):
        pack(_tree(tmp_path / "deep", {deep: ""}), tmp_path / "1.zip")
    empty = tmp_path / "empty"
    (empty / ".git").mkdir(parents=True)
    with pytest.raises(PackError, match="nothing to upload"):
        pack(empty, tmp_path / "2.zip")


@pytest.mark.skipif(os.name != "nt", reason="Windows line endings")
def test_bytes_are_packed_unchanged(tmp_path: Path) -> None:
    root = tmp_path / "p"
    root.mkdir()
    (root / "crlf.py").write_bytes(b"a = 1\r\nb = 2\r\n")
    with zipfile.ZipFile(pack(root, tmp_path / "o.zip").archive) as zf:
        assert zf.read("crlf.py") == b"a = 1\r\nb = 2\r\n"
