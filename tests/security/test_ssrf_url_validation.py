"""SSRF: hostile repository URLs are refused before any connection is made."""

from __future__ import annotations

import pytest

from app.repository.url_validator import UnsafeRepositoryURL, validate_repo_url

ALLOWED = ["github.com", "gitlab.com"]


def public(_host: str) -> list[str]:
    return ["140.82.112.3"]


@pytest.mark.parametrize("url", [
    # wrong scheme / transport
    "file:///etc/passwd",
    "file://C:/Windows/win.ini",
    "git://github.com/octocat/Hello-World",
    "ssh://git@github.com/octocat/Hello-World",
    "git@github.com:octocat/Hello-World.git",
    "ext::sh -c touch% /tmp/pwned",
    "http://github.com/octocat/Hello-World",
    "ftp://github.com/a/b",
    # option injection into git
    "-uhttps://github.com/a/b",
    "--upload-pack=touch /tmp/pwned",
    # credentials, ports, query, fragment
    "https://user:pass@github.com/a/b",
    "https://token@github.com/a/b",
    "https://github.com:8443/a/b",
    "https://github.com:22/a/b",
    "https://github.com/a/b?ref=x",
    "https://github.com/a/b#frag",
    # internal addresses, in every notation
    "https://127.0.0.1/a/b",
    "https://127.1/a/b",
    "https://2130706433/a/b",
    "https://0x7f000001/a/b",
    "https://[::1]/a/b",
    "https://[::ffff:127.0.0.1]/a/b",
    "https://169.254.169.254/latest/meta-data",
    "https://10.0.0.5/a/b",
    "https://localhost/a/b",
    "https://metadata.google.internal/a/b",
    # host lookalikes and allowlist bypass attempts
    "https://github.com.evil.example/a/b",
    "https://evilgithub.com/a/b",
    "https://github.com@evil.example/a/b",
    "https://g\u0456thub.com/a/b",          # Cyrillic i homoglyph
    # path tricks
    "https://github.com/../../a/b",
    "https://github.com/a/%2e%2e/b",
    "https://github.com/a",
    "https://github.com/a\\b/c",
    # whitespace and control characters
    "https://github.com/a/b\n",
    " https://github.com/a/b",
    "https://github.com/a/b\x00",
    "",
    "https://github.com/" + "a" * 400,
])
def test_hostile_urls_are_refused(url: str) -> None:
    with pytest.raises(UnsafeRepositoryURL):
        validate_repo_url(url, ALLOWED, resolver=public)


@pytest.mark.parametrize("addresses", [
    ["127.0.0.1"], ["10.1.2.3"], ["192.168.0.10"], ["172.16.5.4"], ["169.254.169.254"],
    ["100.64.0.1"], ["::1"], ["fe80::1"], ["fc00::1"], ["::ffff:10.0.0.1"], ["0.0.0.0"],
    ["140.82.112.3", "10.0.0.1"],   # one bad answer among good ones is still a refusal
])
def test_allowlisted_host_resolving_internally_is_refused(addresses: list[str]) -> None:
    with pytest.raises(UnsafeRepositoryURL, match="non-public"):
        validate_repo_url("https://github.com/octocat/Hello-World", ALLOWED, resolver=lambda _h: addresses)


def test_resolution_failure_is_a_refusal() -> None:
    def broken(_host: str) -> list[str]:
        raise OSError("no DNS")

    with pytest.raises(UnsafeRepositoryURL, match="resolve"):
        validate_repo_url("https://github.com/octocat/Hello-World", ALLOWED, resolver=broken)
    with pytest.raises(UnsafeRepositoryURL, match="resolve"):
        validate_repo_url("https://github.com/octocat/Hello-World", ALLOWED, resolver=lambda _h: [])


def test_ip_literals_are_refused_by_the_ip_rule_itself() -> None:
    # Regression: the refusal used to be raised inside `except ValueError` and swallowed.
    for url in ("https://169.254.169.254/a/b", "https://[::1]/a/b"):
        with pytest.raises(UnsafeRepositoryURL, match="IP-address"):
            validate_repo_url(url, ALLOWED + ["::1", "169.254.169.254"], resolver=public)


@pytest.mark.parametrize("url, expected", [
    ("https://github.com/octocat/Hello-World", "https://github.com/octocat/Hello-World.git"),
    ("https://github.com/octocat/Hello-World.git", "https://github.com/octocat/Hello-World.git"),
    ("https://GitHub.com/octocat/Hello-World/", "https://github.com/octocat/Hello-World.git"),
    ("https://github.com:443/octocat/Hello-World", "https://github.com/octocat/Hello-World.git"),
    ("https://gitlab.com/group/sub/project", "https://gitlab.com/group/sub/project.git"),
])
def test_valid_urls_are_normalised(url: str, expected: str) -> None:
    assert validate_repo_url(url, ALLOWED, resolver=public).url == expected
