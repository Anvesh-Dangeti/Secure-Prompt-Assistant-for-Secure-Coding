"""Configuration loads safely and keeps its one secret out of reprs."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import PROJECT_ROOT, Settings, get_settings


def test_env_overrides_are_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_SCANNER_TIMEOUT_SECONDS", "42")
    get_settings.cache_clear()
    assert get_settings().scanner_timeout_seconds == 42


def test_allowed_hosts_accept_comma_separated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPA_ALLOWED_GIT_HOSTS", "GitHub.com, gitlab.com. ,")
    get_settings.cache_clear()
    assert get_settings().allowed_git_hosts == ["github.com", "gitlab.com"]


def test_api_key_never_appears_in_repr() -> None:
    settings = get_settings()
    assert settings.api_key is not None
    assert settings.api_key.get_secret_value() not in repr(settings)
    assert settings.api_key.get_secret_value() not in str(settings.model_dump())


def test_out_of_range_limits_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(scanner_timeout_seconds=0)
    with pytest.raises(ValidationError):
        Settings(log_level="LOUD")


def test_relative_paths_resolve_against_project_root() -> None:
    settings = Settings(scratch_root="relative-scratch")
    assert settings.scratch_root == PROJECT_ROOT / "relative-scratch"
