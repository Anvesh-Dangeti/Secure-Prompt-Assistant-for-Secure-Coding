"""Where a connection is remembered -- and where the token is not.

Two files, deliberately apart:

* **The link**, ``<project>/.spa/connection.json``: server address, project
  name and id. It holds no secret, so it is harmless if it is committed or
  shared, and it lets ``spa`` find the connection from any sub-folder.
* **The token**, in the user's own configuration directory
  (``%APPDATA%\\spa\\credentials.json`` on Windows,
  ``~/.config/spa/credentials.json`` elsewhere, file mode 0600). It never lives
  inside the project, so it cannot be committed or uploaded with the code.

``SPA_TOKEN`` in the environment takes precedence -- the CI path, where the
token comes from the CI system's secret store. ``SPA_CONFIG_DIR`` moves the
credentials file (portable installs, tests).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from spa_connect.errors import ConnectError

LINK_DIR = ".spa"
LINK_FILE = "connection.json"
_TOKEN_RE = re.compile(r"^spa_pat_[A-Za-z0-9_-]{43}$")


@dataclass(frozen=True)
class Link:
    root: Path            # the project folder: the one that holds .spa/
    server: str
    project: str
    project_id: int


def valid_token(text: str) -> bool:
    return bool(_TOKEN_RE.match(text))


# ---- the link (in the project) ---------------------------------------------------------------


def write_link(root: Path, server: str, project: str, project_id: int) -> Path:
    folder = root / LINK_DIR
    folder.mkdir(exist_ok=True)
    target = folder / LINK_FILE
    target.write_text(json.dumps({"server": server, "project": project, "project_id": project_id}, indent=2) + "\n",
                      encoding="utf-8")
    return target


def find_link(start: Path) -> Link | None:
    """The nearest ``.spa/connection.json`` at or above ``start`` (as git finds ``.git``)."""
    for folder in (start, *start.parents):
        candidate = folder / LINK_DIR / LINK_FILE
        if candidate.is_file() and not candidate.is_symlink():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                return Link(folder, str(data["server"]), str(data["project"]), int(data["project_id"]))
            except (ValueError, KeyError, TypeError) as exc:
                raise ConnectError(f"{candidate} is damaged; run `spa connect` again") from exc
    return None


def remove_link(root: Path) -> None:
    target = root / LINK_DIR / LINK_FILE
    if target.is_file():
        target.unlink()
    try:
        (root / LINK_DIR).rmdir()
    except OSError:
        pass          # not empty, or already gone: leave it


# ---- the token (outside the project) -----------------------------------------------------------


def credentials_path() -> Path:
    override = os.environ.get("SPA_CONFIG_DIR")
    if override:
        base = Path(override)
    elif os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "spa"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "spa"
    return base / "credentials.json"


def _key(server: str, project: str) -> str:
    return f"{server}#{project}"


def _load_all() -> dict[str, str]:
    path = credentials_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ConnectError(f"{path} is damaged; delete it and run `spa connect` again") from exc
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def _save_all(tokens: dict[str, str]) -> None:
    path = credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    # Created owner-only from the first byte (POSIX); on Windows the user profile's ACL protects it.
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(tokens, out, indent=2)
    os.replace(temporary, path)
    if os.name != "nt":
        os.chmod(path, 0o600)


def save_token(server: str, project: str, token: str) -> Path:
    tokens = _load_all()
    tokens[_key(server, project)] = token
    _save_all(tokens)
    return credentials_path()


def load_token(server: str, project: str) -> str | None:
    from_env = os.environ.get("SPA_TOKEN", "").strip()
    if from_env:
        return from_env
    return _load_all().get(_key(server, project))


def forget_token(server: str, project: str) -> bool:
    tokens = _load_all()
    if tokens.pop(_key(server, project), None) is None:
        return False
    _save_all(tokens)
    return True
