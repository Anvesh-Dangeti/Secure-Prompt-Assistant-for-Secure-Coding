"""Scratch directories with guaranteed cleanup.

Clones and extracted archives contain untrusted -- and possibly sensitive --
code. They live only inside ``settings.scratch_root`` and are deleted on every
exit path, including exceptions and timeouts.

Windows detail: git marks its object files read-only, so a plain
``shutil.rmtree`` fails half-way and leaves the clone behind. ``remove_tree``
clears the read-only bit and retries.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.paths import is_within

log = get_logger(__name__)


def scratch_root() -> Path:
    root = get_settings().scratch_root
    root.mkdir(parents=True, exist_ok=True)
    return root


def _make_writable_and_retry(func, path, _exc) -> None:  # noqa: ANN001
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    func(path)


def remove_tree(path: Path) -> None:
    """Delete ``path`` recursively -- but only if it lies inside the scratch root."""
    if not path.exists():
        return
    # Defence against a bug elsewhere turning cleanup into deletion of real data.
    if not is_within(path, scratch_root()) or os.path.realpath(path) == os.path.realpath(scratch_root()):
        raise PermissionError(f"refusing to delete outside scratch root: {path}")
    shutil.rmtree(path, onexc=_make_writable_and_retry)


@contextmanager
def scratch_dir(prefix: str = "spa-") -> Iterator[Path]:
    """Create a private temporary directory under the scratch root; always remove it."""
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=scratch_root()))
    try:
        yield path
    finally:
        try:
            remove_tree(path)
        except OSError:
            # Never mask the original exception; record the leak instead.
            log.error("scratch cleanup failed", extra={"path": str(path)})


def copy_trusted_tree(source: Path, dest: Path, exclude: Iterable[str] = ()) -> None:
    """Copy a *trusted local* directory (a fixture, a developer's own checkout) into scratch.

    Directories named in ``exclude`` are skipped and every symlink is removed
    from the copy, so nothing that is later scanned, patched or tested in
    scratch can point back out of it.
    """
    shutil.copytree(source, dest, symlinks=True, ignore=shutil.ignore_patterns(*exclude))
    for path in list(dest.rglob("*")):
        if path.is_symlink():
            path.unlink()  # never follow links out of the tree
