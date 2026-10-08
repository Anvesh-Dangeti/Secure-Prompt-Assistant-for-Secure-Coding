"""Path containment helpers.

Every path derived from untrusted input (archive member names, scanner-reported
file paths, repository contents) must be checked with ``is_within`` before it is
read, written or deleted. ``os.path.realpath`` resolves ``..`` and symlinks, and
``normcase`` makes the comparison case-insensitive on Windows.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath


class PathTraversalError(ValueError):
    """A path resolved outside the directory it was required to stay in."""


def _canon(path: Path | str) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def is_within(child: Path | str, parent: Path | str) -> bool:
    """True if ``child`` resolves to ``parent`` or somewhere beneath it."""
    child_c, parent_c = _canon(child), _canon(parent)
    try:
        return os.path.commonpath([child_c, parent_c]) == parent_c
    except ValueError:  # different drives on Windows
        return False


def safe_join(base: Path, *parts: str) -> Path:
    """Join ``parts`` onto ``base`` and refuse any result that escapes ``base``."""
    candidate = base.joinpath(*parts)
    if not is_within(candidate, base):
        raise PathTraversalError(f"path escapes its base directory: {'/'.join(parts)!r}")
    return candidate


def repo_relative(path: str | Path, root: Path) -> str | None:
    """Normalise a scanner-reported path to a repo-relative POSIX string.

    Returns ``None`` if the path points outside ``root``. Repo-relative paths are
    what make fingerprints portable: every scan runs in a fresh scratch directory,
    so an absolute path would give every finding a new identity on every scan.
    """
    raw = os.fspath(path)
    if raw.startswith("file://"):
        raw = raw[len("file://"):]
        if len(raw) > 2 and raw[0] == "/" and raw[2] == ":":  # file:///C:/...
            raw = raw[1:]
    raw = raw.replace("\\", "/")
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    if not is_within(candidate, root):
        return None
    rel = os.path.relpath(os.path.realpath(candidate), os.path.realpath(root))
    posix = PurePosixPath(rel.replace("\\", "/")).as_posix()
    return "" if posix == "." else posix
