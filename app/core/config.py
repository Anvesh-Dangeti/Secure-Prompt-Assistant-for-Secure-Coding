"""Typed application configuration.

All settings come from environment variables prefixed ``SPA_`` (or a local
``.env`` file). Nothing secret is hard-coded: the only secret, the API key, is a
``SecretStr`` so it never appears in ``repr()``, logs, or error messages.

Every resource limit used to contain untrusted input (archives, clones, scanner
output) lives here, so the security envelope of the system is reviewable in one
place rather than scattered as magic numbers.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Repository root: app/core/config.py -> parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[2]

MB = 1024 * 1024


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SPA_",
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- storage -------------------------------------------------------
    database_url: str = f"sqlite:///{(PROJECT_ROOT / 'data' / 'spa.db').as_posix()}"
    # Every clone, extraction and scanner report lives under here and is deleted
    # after use. Subprocesses may only run with a working directory inside it.
    scratch_root: Path = PROJECT_ROOT / "scratch"

    # ---- API authentication -------------------------------------------
    # No default. If unset, every protected endpoint refuses to serve (fail closed).
    api_key: SecretStr | None = None

    log_level: str = "INFO"

    # ---- subprocess limits --------------------------------------------
    scanner_timeout_seconds: int = Field(300, ge=5, le=3600)
    clone_timeout_seconds: int = Field(120, ge=5, le=1800)
    max_tool_output_bytes: int = Field(64 * MB, ge=1024)
    # Refuse to run scanners as root/Administrator: they parse untrusted code.
    allow_elevated: bool = False

    # ---- untrusted archive limits (ZIP upload) ------------------------
    max_upload_bytes: int = Field(50 * MB, ge=1024)
    max_extracted_bytes: int = Field(200 * MB, ge=1024)
    max_archive_files: int = Field(5000, ge=1)
    max_archive_file_bytes: int = Field(20 * MB, ge=1024)
    max_compression_ratio: int = Field(100, ge=2)
    max_path_depth: int = Field(24, ge=1)

    # ---- untrusted repository limits (git clone) -----------------------
    max_repo_bytes: int = Field(300 * MB, ge=1024)
    max_repo_files: int = Field(20000, ge=1)
    # Allowlist, not denylist: only these hosts may be cloned from (SSRF control).
    allowed_git_hosts: Annotated[list[str], NoDecode] = ["github.com", "gitlab.com", "bitbucket.org"]

    # ---- scanner binaries (optional explicit paths) --------------------
    semgrep_bin: Path | None = None
    bandit_bin: Path | None = None
    gitleaks_bin: Path | None = None
    pip_audit_bin: Path | None = None
    # Pinned Semgrep ruleset snapshot (see scripts/fetch_semgrep_rules.py).
    semgrep_rules: Path = PROJECT_ROOT / "rules" / "vendor" / "semgrep_p_python.yaml"

    # ---- AI layer: data minimisation --------------------------------------
    # Lines of code around a finding that may leave the process. A function
    # no longer than max_context_lines is sent whole; anything longer is
    # clipped to context_radius lines either side of the finding.
    context_radius: int = Field(10, ge=1, le=50)
    max_context_lines: int = Field(40, ge=5, le=200)
    max_context_file_bytes: int = Field(1 * MB, ge=1024)
    # Prompts above this estimated size are flagged by the linter (C1).
    prompt_token_budget: int = Field(1500, ge=200, le=32000)

    # ---- AI layer: providers ----------------------------------------------
    # "template" needs no model at all (developer mode default). "ollama" is
    # the local model used for lab-mode experiments.
    llm_provider: str = "template"
    # Loopback only: source context must never leave this machine by
    # misconfiguration. A hosted provider would be a separate, explicit class.
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5-coder:7b-instruct"
    llm_timeout_seconds: int = Field(180, ge=5, le=1800)
    llm_seed: int = 42
    llm_num_ctx: int = Field(4096, ge=1024, le=32768)
    max_llm_response_bytes: int = Field(256 * 1024, ge=1024)

    @field_validator("allowed_git_hosts", mode="before")
    @classmethod
    def _split_hosts(cls, value: object) -> object:
        # Accept "github.com,gitlab.com" from the environment.
        if isinstance(value, str):
            value = [part for part in value.split(",")]
        if isinstance(value, list):
            return [str(h).strip().lower().rstrip(".") for h in value if str(h).strip()]
        return value

    @field_validator("log_level")
    @classmethod
    def _valid_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"invalid log level: {value}")
        return level

    @field_validator("llm_provider")
    @classmethod
    def _known_provider(cls, value: str) -> str:
        name = value.strip().lower()
        if name not in {"template", "ollama"}:
            raise ValueError(f"unknown LLM provider: {value}")
        return name

    @field_validator("scratch_root", "semgrep_rules", mode="after")
    @classmethod
    def _absolute(cls, value: Path) -> Path:
        return value if value.is_absolute() else (PROJECT_ROOT / value)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings. Tests call ``get_settings.cache_clear()``."""
    return Settings()
