"""Secrets never survive into logs, stored snippets, or fingerprints."""

from __future__ import annotations

import io
import json
import logging

import pytest

from app.core.logging import JsonFormatter, RedactionFilter
from app.core.redaction import PLACEHOLDER, mask_secret, redact

SECRETS = {
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "github": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "stripe": "sk_live_" + "51H8xQ2eZvKYlo2C0aBcDeFgHiJkLmNoP",
    "slack": "xoxb-" + "123456789012-abcdefghijkl",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
}


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_known_token_formats_are_redacted(name: str) -> None:
    secret = SECRETS[name]
    out = redact(f"value={secret} trailing")
    assert secret not in out
    assert PLACEHOLDER in out


@pytest.mark.parametrize(
    "line, secret",
    [
        ('DB_PASSWORD = "SuperSecret123!"', "SuperSecret123!"),
        ("api_key: 'abc123xyz'", "abc123xyz"),
        ('config["secret"] = "s3cr3t-value"', "s3cr3t-value"),
        ("https://alice:hunter22@github.com/org/repo.git", "hunter22"),
        ("Authorization: Bearer abcdef0123456789", "abcdef0123456789"),
        ("GET /x?token=deadbeefcafe&x=1", "deadbeefcafe"),
    ],
)
def test_generic_secret_shapes_are_redacted(line: str, secret: str) -> None:
    assert secret not in redact(line)


def test_private_key_block_is_redacted() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    assert "MIIEowIBAAKCAQEA" not in redact(f"key:\n{pem}\n")


def test_ordinary_code_is_left_alone() -> None:
    code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
    assert redact(code) == code


def test_redaction_is_deterministic_so_fingerprints_stay_stable() -> None:
    line = 'API_TOKEN = "sk_live_' + 'AAAAAAAAAAAAAAAAAAAAAA"'
    rotated = 'API_TOKEN = "sk_live_' + 'BBBBBBBBBBBBBBBBBBBBBB"'
    # Rotating a hard-coded secret is not a fix: the redacted form is identical.
    assert redact(line) == redact(rotated)


def test_mask_secret_removes_exact_value() -> None:
    line = 'KEY = "Zx9-unusual-format-secret"'
    assert "Zx9-unusual-format-secret" not in mask_secret(line, "Zx9-unusual-format-secret")


def _capture(logger_name: str) -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())
    logger = logging.getLogger(logger_name)
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    return logger, stream


def test_log_messages_args_and_extras_are_redacted() -> None:
    logger, stream = _capture("test.redaction.msg")
    logger.info("cloning %s", "https://bob:pa55word@github.com/x/y", extra={"token_hint": SECRETS["github"]})
    record = json.loads(stream.getvalue())
    assert "pa55word" not in stream.getvalue()
    assert SECRETS["github"] not in stream.getvalue()
    assert record["msg"].startswith("cloning https://")


def test_exception_tracebacks_are_redacted() -> None:
    logger, stream = _capture("test.redaction.exc")
    try:
        raise RuntimeError(f"auth failed with {SECRETS['stripe']}")
    except RuntimeError:
        logger.exception("boom")
    assert SECRETS["stripe"] not in stream.getvalue()
