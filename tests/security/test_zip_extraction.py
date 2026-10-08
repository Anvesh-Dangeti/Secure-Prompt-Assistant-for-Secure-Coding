"""Zip-slip, symlinks, bombs and Windows name tricks are refused; nothing escapes."""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.core.scratch import scratch_dir
from app.repository.zip_extract import UnsafeArchiveError, extract_zip


def _zip(path: Path, entries: list[tuple[str, bytes]], *, symlink: str | None = None,
         encrypted: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if name == symlink:
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, data)
    if encrypted:
        raw = bytearray(path.read_bytes())
        # Set the "encrypted" general-purpose flag bit on every header.
        for sig in (b"PK\x03\x04", b"PK\x01\x02"):
            start = 0
            while (i := raw.find(sig, start)) != -1:
                flag_offset = i + (6 if sig == b"PK\x03\x04" else 8)
                raw[flag_offset] |= 0x01
                start = i + 4
        path.write_bytes(bytes(raw))
    return path


def _extract(entries: list[tuple[str, bytes]], **kw) -> tuple[Path, Path]:  # noqa: ANN003
    work_ctx = scratch_dir("ziptest-")
    work = work_ctx.__enter__()
    archive = _zip(work / "a.zip", entries, **kw)
    dest = work / "out"
    try:
        extract_zip(archive, dest)
    finally:
        listing = sorted(p.relative_to(work).as_posix() for p in work.rglob("*"))
        work_ctx.__exit__(None, None, None)
    return dest, listing  # type: ignore[return-value]


@pytest.mark.parametrize("name", [
    "../evil.py",
    "../../../../Windows/evil.py",
    "a/../../evil.py",
    "..\\evil.py",
    "a\\..\\..\\evil.py",
    "/etc/cron.d/evil",
    "\\Windows\\evil.py",
    "C:/Windows/evil.py",
    "C:evil.py",
    "app.py:hidden_stream",
    "CON",
    "nul.txt",
    "aux.py",
    "trailing-dot.",
])
def test_unsafe_member_names_are_refused(name: str) -> None:
    with pytest.raises(UnsafeArchiveError):
        _extract([("ok.py", b"x = 1\n"), (name, b"pwned\n")])


def test_nothing_is_written_when_a_member_is_unsafe() -> None:
    with scratch_dir("ziptest-") as work:
        archive = _zip(work / "a.zip", [("first.py", b"x\n"), ("../evil.py", b"pwned\n")])
        with pytest.raises(UnsafeArchiveError):
            extract_zip(archive, work / "out")
        # Validation happens before extraction: not even the safe member was written.
        assert not (work / "out" / "first.py").exists()
        assert not (work / "evil.py").exists()


def test_symlink_members_are_refused() -> None:
    with pytest.raises(UnsafeArchiveError, match="symbolic"):
        _extract([("ok.py", b"x\n"), ("link", b"/etc/passwd")], symlink="link")


def test_encrypted_members_are_refused() -> None:
    with pytest.raises(UnsafeArchiveError):
        _extract([("ok.py", b"x\n")], encrypted="ok.py")


def test_case_insensitive_duplicates_are_refused() -> None:
    with pytest.raises(UnsafeArchiveError, match="duplicate"):
        _extract([("App.py", b"a\n"), ("app.py", b"b\n")])


def test_too_many_files(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_MAX_ARCHIVE_FILES", "5")
    get_settings.cache_clear()
    with pytest.raises(UnsafeArchiveError, match="entries"):
        _extract([(f"f{i}.py", b"x\n") for i in range(6)])


def test_too_deep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_MAX_PATH_DEPTH", "3")
    get_settings.cache_clear()
    with pytest.raises(UnsafeArchiveError, match="deeply"):
        _extract([("a/b/c/d.py", b"x\n")])


def test_zip_bomb_ratio_is_refused() -> None:
    # 20 MiB of zeros compresses ~1000:1 -- far beyond the ratio cap.
    with pytest.raises(UnsafeArchiveError, match="ratio|size"):
        _extract([("bomb.bin", b"\x00" * (20 * 1024 * 1024 - 1))])


def test_total_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_MAX_EXTRACTED_BYTES", "4096")
    get_settings.cache_clear()
    with pytest.raises(UnsafeArchiveError, match="size"):
        _extract([("a.py", b"a" * 3000), ("b.py", b"b" * 3000)])


def test_not_a_zip_is_refused() -> None:
    with scratch_dir("ziptest-") as work:
        fake = work / "fake.zip"
        fake.write_bytes(b"#!/bin/sh\necho pwned\n")
        with pytest.raises(UnsafeArchiveError, match="not a ZIP"):
            extract_zip(fake, work / "out")


def test_valid_archive_is_extracted_and_single_top_dir_unwrapped() -> None:
    with scratch_dir("ziptest-") as work:
        archive = _zip(work / "a.zip", [("repo-main/app.py", b"x = 1\n"), ("repo-main/pkg/m.py", b"y = 2\n")])
        result = extract_zip(archive, work / "out")
        assert result.root.name == "repo-main"
        assert (result.root / "pkg" / "m.py").read_text() == "y = 2\n"
        assert result.files == 2 and len(result.sha256) == 64
