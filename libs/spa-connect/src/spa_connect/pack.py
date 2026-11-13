"""Pack the project folder for upload: source code in, everything else out.

* Folders that are never source -- version-control data, virtual environments,
  dependency caches -- are skipped, the same list the server's scanners skip.
* **Local secret files** (``.env``, ``.env.*``; ``.env.example`` is kept) are
  skipped: they are not committed code, and live credentials should not travel
  to a server. A secret hard-coded *in source* is still uploaded, because
  finding it is the point.
* **Symbolic links and junctions are skipped**, never followed, so a link cannot
  pull files from outside the project into the upload.
* ``.spaignore`` (one glob per line, ``#`` comments) excludes anything else,
  such as large data folders.
* The server's limits are checked here first, so an oversized project fails
  with a clear message before anything is sent. The server checks them again;
  this check is for the developer's convenience, not for security.
"""

from __future__ import annotations

import fnmatch
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from spa_connect.config import LINK_DIR
from spa_connect.errors import ConnectError

EXCLUDED_DIRS = frozenset({".git", ".venv", "venv", "env", "node_modules", "site-packages", "__pycache__", ".tox",
                           LINK_DIR})
SECRET_FILES = ("*.env", ".env", ".env.*")
KEEP_FILES = frozenset({".env.example", ".env.sample", ".env.template"})
IGNORE_FILE = ".spaignore"

# The server's default limits (SPA_MAX_UPLOAD_BYTES and friends).
MB = 1024 * 1024
MAX_UPLOAD_BYTES = 50 * MB
MAX_TOTAL_BYTES = 200 * MB
MAX_FILES = 5000
MAX_FILE_BYTES = 20 * MB
MAX_DEPTH = 24


class PackError(ConnectError):
    pass


@dataclass
class Packed:
    archive: Path
    files: int = 0
    total_bytes: int = 0
    skipped_links: list[str] = field(default_factory=list)
    skipped_secrets: list[str] = field(default_factory=list)
    ignored: int = 0


def read_ignore(root: Path) -> list[str]:
    path = root / IGNORE_FILE
    if not path.is_file() or path.is_symlink():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def is_ignored(rel: str, is_dir: bool, patterns: list[str]) -> bool:
    """gitignore-like: a plain name matches anywhere; a leading '/' or an inner '/' anchors to the project root;
    a trailing '/' matches folders only."""
    name = PurePosixPath(rel).name
    for pattern in patterns:
        dir_only = pattern.endswith("/")
        anchored = pattern.startswith("/")
        pattern = pattern.strip("/")
        if not pattern or (dir_only and not is_dir):
            continue
        if anchored or "/" in pattern:
            if fnmatch.fnmatchcase(rel, pattern):
                return True
        elif fnmatch.fnmatchcase(name, pattern):
            return True
    return False


def _is_link(path: Path) -> bool:
    isjunction = getattr(os.path, "isjunction", None)      # Python 3.12+
    return path.is_symlink() or bool(isjunction and isjunction(path))


def _secret_file(name: str) -> bool:
    return name not in KEEP_FILES and any(fnmatch.fnmatchcase(name, p) for p in SECRET_FILES)


def pack(root: Path, archive: Path) -> Packed:
    patterns = read_ignore(root)
    packed = Packed(archive)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath)
            rel_dir = here.relative_to(root)
            keep = []
            for name in sorted(dirnames):
                rel = (rel_dir / name).as_posix()
                if name in EXCLUDED_DIRS:
                    continue
                if _is_link(here / name):
                    packed.skipped_links.append(rel)
                elif is_ignored(rel, True, patterns):
                    packed.ignored += 1
                else:
                    keep.append(name)
            dirnames[:] = keep                     # os.walk descends only into these
            for name in sorted(filenames):
                path, rel = here / name, (rel_dir / name).as_posix()
                if _is_link(path):
                    packed.skipped_links.append(rel)
                    continue
                if not path.is_file():
                    continue                       # sockets, devices
                if _secret_file(name):
                    packed.skipped_secrets.append(rel)
                    continue
                if is_ignored(rel, False, patterns):
                    packed.ignored += 1
                    continue
                _check_limits(packed, rel, path.stat().st_size)
                zf.write(path, rel)
    size = archive.stat().st_size
    if size > MAX_UPLOAD_BYTES:
        raise PackError(f"the packed project is {size / MB:.0f} MB; the server accepts {MAX_UPLOAD_BYTES // MB} MB. "
                        f"Exclude data or build folders in {IGNORE_FILE}.")
    if packed.files == 0:
        raise PackError("nothing to upload: the folder has no files after exclusions")
    return packed


def _check_limits(packed: Packed, rel: str, size: int) -> None:
    hint = f"Exclude it in {IGNORE_FILE} if it is not source code."
    if len(PurePosixPath(rel).parts) > MAX_DEPTH:
        raise PackError(f"{rel} is nested more than {MAX_DEPTH} folders deep. {hint}")
    if size > MAX_FILE_BYTES:
        raise PackError(f"{rel} is {size / MB:.0f} MB; the server accepts files up to {MAX_FILE_BYTES // MB} MB. {hint}")
    packed.files += 1
    packed.total_bytes += size
    if packed.files > MAX_FILES:
        raise PackError(f"more than {MAX_FILES} files to upload. Exclude data or build folders in {IGNORE_FILE}.")
    if packed.total_bytes > MAX_TOTAL_BYTES:
        raise PackError(f"more than {MAX_TOTAL_BYTES // MB} MB of files to upload. Exclude data or build folders "
                        f"in {IGNORE_FILE}.")
