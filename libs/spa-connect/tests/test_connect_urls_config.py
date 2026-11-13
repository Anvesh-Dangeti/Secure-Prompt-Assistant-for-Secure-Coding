"""Server addresses are validated; the token is stored outside the project, owner-only, and never in the link."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from spa_connect.config import (
    credentials_path, find_link, forget_token, load_token, remove_link, save_token, valid_token, write_link,
)
from spa_connect.errors import ConnectError
from spa_connect.urls import normalise_server

TOKEN = "spa_pat_" + "A" * 43


@pytest.fixture(autouse=True)
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_CONFIG_DIR", str(tmp_path / "home-config"))
    monkeypatch.delenv("SPA_TOKEN", raising=False)


@pytest.mark.parametrize(("raw", "expected"), [
    ("https://spa.example.edu", "https://spa.example.edu"),
    ("  HTTPS://SPA.Example.edu:8443/ ", "https://spa.example.edu:8443"),
    ("https://example.edu/spa/", "https://example.edu/spa"),
    ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
    ("http://localhost:8000/", "http://localhost:8000"),
    ("http://[::1]:8000", "http://[::1]:8000"),
])
def test_good_addresses_are_normalised(raw: str, expected: str) -> None:
    assert normalise_server(raw) == expected


@pytest.mark.parametrize(("raw", "message"), [
    ("", "give the server"), ("spa.example.edu", "https://"), ("ftp://spa.example.edu", "https://"),
    ("file:///etc/passwd", "https://"), ("http://spa.example.edu", "only allowed for this machine"),
    ("http://10.0.0.5:8000", "only allowed for this machine"), ("https://user:pw@spa.example.edu", "user name"),
    ("https://spa.example.edu?x=1", "'?'"), ("https://spa.example.edu#x", "'?'"), ("https://", "no host"),
    ("https://spa.example.edu:99999", "port"), ("https://spa example.edu", "give the server"),
    ("http://127.0.0.1.evil.com", "only allowed"),
])
def test_bad_addresses_are_refused(raw: str, message: str) -> None:
    with pytest.raises(ConnectError, match=message):
        normalise_server(raw)


def test_token_format() -> None:
    assert valid_token(TOKEN)
    for bad in ("", "spa_pat_short", TOKEN + "x", "Bearer " + TOKEN, TOKEN[:-1] + "!", " " + TOKEN):
        assert not valid_token(bad)


def test_the_link_holds_no_secret_and_is_found_from_subfolders(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "src" / "deep").mkdir(parents=True)
    save_token("https://spa.example.edu", "portal", TOKEN)
    link_file = write_link(root, "https://spa.example.edu", "portal", 3)
    assert TOKEN not in link_file.read_text(encoding="utf-8")
    assert json.loads(link_file.read_text(encoding="utf-8")) == {
        "server": "https://spa.example.edu", "project": "portal", "project_id": 3}
    link = find_link(root / "src" / "deep")
    assert link is not None and link.root == root and link.project_id == 3
    remove_link(root)
    assert find_link(root) is None and not (root / ".spa").exists()


def test_a_damaged_link_is_reported(tmp_path: Path) -> None:
    (tmp_path / ".spa").mkdir()
    (tmp_path / ".spa" / "connection.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(ConnectError, match="damaged"):
        find_link(tmp_path)


def test_tokens_are_kept_per_server_and_project(tmp_path: Path) -> None:
    other = "spa_pat_" + "B" * 43
    save_token("https://a.example", "portal", TOKEN)
    save_token("https://b.example", "portal", other)
    assert load_token("https://a.example", "portal") == TOKEN
    assert load_token("https://b.example", "portal") == other
    assert load_token("https://a.example", "other") is None
    assert credentials_path().parent == tmp_path / "home-config"
    assert forget_token("https://a.example", "portal") is True
    assert forget_token("https://a.example", "portal") is False
    assert load_token("https://a.example", "portal") is None
    assert not list(credentials_path().parent.glob("*.tmp"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_the_credentials_file_is_owner_only() -> None:
    path = save_token("https://a.example", "portal", TOKEN)
    assert path.stat().st_mode & 0o777 == 0o600


def test_the_environment_token_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    save_token("https://a.example", "portal", TOKEN)
    monkeypatch.setenv("SPA_TOKEN", "spa_pat_" + "C" * 43)
    assert load_token("https://a.example", "portal").startswith("spa_pat_C")


def test_default_location_is_the_users_config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SPA_CONFIG_DIR")
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    expected = (tmp_path / "roaming" / "spa") if os.name == "nt" else (tmp_path / "xdg" / "spa")
    assert credentials_path() == expected / "credentials.json"
