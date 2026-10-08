"""Safe extraction of an uploaded ZIP archive.

``zipfile.extractall`` is not safe for untrusted archives. Every member is
checked before anything is written, then written by streaming with a running
byte count:

* **Zip-slip**: absolute paths, drive letters, ``..`` segments and
  backslash-separated traversal are refused; every target is re-checked with
  ``safe_join`` after normalisation.
* **Symlinks** (Unix mode bits in ``external_attr``) are refused -- a link could
  point anywhere once extracted.
* **Windows-specific names**: ``:`` (NTFS alternate data streams) and reserved
  device names (``CON``, ``NUL``, ``COM1``...) are refused, as are names that
  collide case-insensitively.
* **Bombs**: caps on member count, path depth, per-file size, total size and
  compression ratio; declared sizes are not trusted -- the stream is counted.
* Encrypted members are refused; nested archives are left as inert files.
"""

from __future__ import annotations

import hashlib
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.core.paths import PathTraversalError, safe_join

_DRIVE = re.compile(r"^[A-Za-z]:")
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
_RATIO_MIN_BYTES = 1024 * 1024  # small files legitimately compress very well


class UnsafeArchiveError(ValueError):
    """The archive was refused. The message is safe to show to the user."""


@dataclass(frozen=True)
class ExtractedArchive:
    root: Path        # the directory to scan (unwrapped if the archive had one top-level dir)
    sha256: str
    files: int
    bytes: int


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _member_parts(name: str) -> list[str]:
    if "\x00" in name or ":" in name or _DRIVE.match(name) or name.startswith(("/", "\\")):
        raise UnsafeArchiveError(f"unsafe member path: {name[:120]!r}")
    parts = [p for p in re.split(r"[\\/]+", name) if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnsafeArchiveError(f"path traversal in member: {name[:120]!r}")
    for part in parts:
        if part.split(".", 1)[0].lower() in _RESERVED or part.endswith((" ", ".")):
            raise UnsafeArchiveError(f"reserved or invalid file name: {part[:60]!r}")
    return parts


def _validate(infos: list[zipfile.ZipInfo]) -> None:
    s = get_settings()
    if len(infos) > s.max_archive_files:
        raise UnsafeArchiveError(f"archive has more than {s.max_archive_files} entries")
    if sum(i.file_size for i in infos) > s.max_extracted_bytes:
        raise UnsafeArchiveError("archive expands beyond the size limit")
    seen: set[str] = set()
    for info in infos:
        parts = _member_parts(info.filename)
        if len(parts) > s.max_path_depth:
            raise UnsafeArchiveError("archive nests directories too deeply")
        key = "/".join(parts).lower()
        if key in seen and not info.is_dir():
            raise UnsafeArchiveError(f"duplicate member: {info.filename[:120]!r}")
        seen.add(key)
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise UnsafeArchiveError(f"symbolic links are not allowed: {info.filename[:120]!r}")
        if info.flag_bits & 0x1:
            raise UnsafeArchiveError("encrypted archives are not supported")
        if info.file_size > s.max_archive_file_bytes:
            raise UnsafeArchiveError(f"member too large: {info.filename[:120]!r}")
        if info.file_size > _RATIO_MIN_BYTES and info.file_size / max(info.compress_size, 1) > s.max_compression_ratio:
            raise UnsafeArchiveError("compression ratio too high (possible zip bomb)")


def extract_zip(archive: Path, dest: Path) -> ExtractedArchive:
    """Extract ``archive`` into ``dest`` (an empty scratch directory)."""
    s = get_settings()
    with archive.open("rb") as handle:
        if handle.read(4) not in ZIP_MAGIC:
            raise UnsafeArchiveError("not a ZIP archive")
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise UnsafeArchiveError("corrupt ZIP archive") from exc

    dest.mkdir(parents=True, exist_ok=True)
    written_total, files = 0, 0
    with zf:
        infos = zf.infolist()
        _validate(infos)
        for info in infos:
            parts = _member_parts(info.filename)
            if not parts:
                continue
            try:
                target = safe_join(dest, *parts)
            except PathTraversalError as exc:
                raise UnsafeArchiveError(str(exc)) from exc
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            try:
                with zf.open(info) as src, target.open("xb") as out:
                    for chunk in iter(lambda: src.read(1 << 16), b""):
                        written += len(chunk)
                        written_total += len(chunk)
                        # Count real bytes: a forged header can understate sizes.
                        if written > s.max_archive_file_bytes or written_total > s.max_extracted_bytes:
                            raise UnsafeArchiveError("archive expands beyond the size limit")
                        out.write(chunk)
            except (zipfile.BadZipFile, RuntimeError, EOFError) as exc:
                raise UnsafeArchiveError(f"corrupt member: {info.filename[:120]!r}") from exc
            except FileExistsError as exc:
                raise UnsafeArchiveError(f"duplicate member: {info.filename[:120]!r}") from exc
            files += 1

    children = [c for c in dest.iterdir()]
    root = children[0] if len(children) == 1 and children[0].is_dir() else dest
    return ExtractedArchive(root=root, sha256=sha256_of(archive), files=files, bytes=written_total)
