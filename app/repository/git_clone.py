"""Shallow, hardened ``git clone`` of a validated public repository.

Every option below closes a specific door:

* ``protocol.allow=never`` + ``protocol.https.allow=always`` and
  ``GIT_ALLOW_PROTOCOL=https`` -- no ``file``/``ext``/``ssh`` transport even
  via submodules or redirects.
* ``http.followRedirects=false`` -- the validated host cannot bounce git to
  an internal address.
* ``GIT_CONFIG_NOSYSTEM=1`` + ``GIT_CONFIG_GLOBAL=<null>`` + empty
  ``credential.helper`` -- the user's and system's git configuration is not
  loaded, so no credential helper can attach the operator's GitHub token to
  an attacker-chosen clone (a confused deputy that would let a request read
  the operator's private repositories). Public repositories only.
* ``GIT_TERMINAL_PROMPT=0`` -- never hang waiting for a password.
* ``core.symlinks=false`` -- symlinks are checked out as plain text files,
  so nothing in the tree can point outside it.
* no hooks/filters are configured (no config is loaded), and
  ``--no-recurse-submodules`` -- nothing from the repository executes.
* ``--depth=1 --single-branch --no-tags`` plus a timeout and post-clone size
  and file-count caps bound the resources a hostile repository can consume.
* ``--`` before the URL -- it can never be parsed as an option.

After the commit SHA is recorded, ``.git`` is deleted: the scanners need
only the working tree.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.core.config import get_settings
from app.core.redaction import redact
from app.core.scratch import remove_tree
from app.core.subprocess_runner import run_tool
from app.repository.url_validator import ValidatedRepoURL

_SHA = re.compile(r"^[0-9a-f]{40}$")


class CloneError(RuntimeError):
    """The clone failed or the repository exceeded a limit. Message is user-safe."""


def _git_env() -> dict[str, str]:
    return {
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_LFS_SKIP_SMUDGE": "1",
    }


def _hardening_config() -> list[str]:
    options = [
        "protocol.allow=never",
        "protocol.https.allow=always",
        "http.followRedirects=false",
        "credential.helper=",
        "core.symlinks=false",
        "core.fsmonitor=false",
        "submodule.recurse=false",
    ]
    if os.name == "nt":
        # With system config skipped, use the Windows certificate store for TLS.
        options.append("http.sslBackend=schannel")
    args: list[str] = []
    for option in options:
        args += ["-c", option]
    return args


def clone_args(validated: ValidatedRepoURL, dest: Path) -> list[str]:
    return ["git", *_hardening_config(), "clone", "--depth=1", "--single-branch", "--no-tags",
            "--no-recurse-submodules", "--", validated.url, str(dest)]


def _check_tree_limits(root: Path) -> None:
    settings = get_settings()
    files, total = 0, 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            files += 1
            total += (Path(dirpath) / name).lstat().st_size
            if files > settings.max_repo_files:
                raise CloneError(f"repository has more than {settings.max_repo_files} files")
            if total > settings.max_repo_bytes:
                raise CloneError(f"repository is larger than {settings.max_repo_bytes} bytes")


def clone(validated: ValidatedRepoURL, dest: Path) -> str:
    """Clone into ``dest`` (which must not exist yet). Returns the commit SHA."""
    settings = get_settings()
    proc = run_tool(clone_args(validated, dest), cwd=dest.parent, timeout=settings.clone_timeout_seconds,
                    extra_env=_git_env())
    if proc.timed_out:
        raise CloneError(f"clone exceeded {settings.clone_timeout_seconds}s")
    if proc.returncode != 0:
        last = redact(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "")
        raise CloneError(f"git clone failed: {last[:300]}")

    _check_tree_limits(dest)
    head = run_tool(["git", "-c", "safe.directory=*", "rev-parse", "HEAD"], cwd=dest, timeout=30,
                    extra_env=_git_env())
    sha = head.stdout.strip()
    if head.returncode != 0 or not _SHA.match(sha):
        raise CloneError("could not determine the cloned commit")
    remove_tree(dest / ".git")
    return sha
