"""git is invoked with every hardening option; repository content stays inert."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.scratch import scratch_dir
from app.repository.git_clone import _git_env, clone, clone_args
from app.repository.url_validator import ValidatedRepoURL, validate_repo_url

URL = ValidatedRepoURL(url="https://github.com/octocat/Hello-World.git", host="github.com", path="octocat/Hello-World")


def test_url_is_after_double_dash_and_last() -> None:
    args = clone_args(URL, Path("dest"))
    assert args[-3:] == ["--", URL.url, "dest"]


@pytest.mark.parametrize("option", [
    "protocol.allow=never", "protocol.https.allow=always", "http.followRedirects=false",
    "credential.helper=", "core.symlinks=false", "submodule.recurse=false",
])
def test_hardening_options_present(option: str) -> None:
    args = clone_args(URL, Path("dest"))
    assert option in args and args[args.index(option) - 1] == "-c"


def test_shallow_and_no_submodules() -> None:
    args = clone_args(URL, Path("dest"))
    for flag in ("--depth=1", "--single-branch", "--no-tags", "--no-recurse-submodules"):
        assert flag in args


def test_operator_git_configuration_and_credentials_are_not_loaded() -> None:
    env = _git_env()
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ALLOW_PROTOCOL"] == "https"
    assert "GIT_CONFIG_GLOBAL" in env


@pytest.mark.network
def test_live_shallow_clone_records_sha_and_drops_git_dir() -> None:
    validated = validate_repo_url("https://github.com/octocat/Hello-World", ["github.com"])
    with scratch_dir("clone-") as work:
        sha = clone(validated, work / "src")
        assert len(sha) == 40 and int(sha, 16) >= 0
        assert not (work / "src" / ".git").exists()
        assert (work / "src" / "README").exists()
