"""Repository URL validation -- the SSRF boundary.

A repository URL is the one place a user can make this server open a network
connection to a destination of their choosing. Defences, in order:

1. **Shape**: a short, printable string; no leading ``-`` (option injection
   into ``git``); no ``ext::``/``fd::`` transports, scp-style ``git@host:``
   syntax, credentials, query, fragment, percent-encoding or ``..``.
2. **Scheme allowlist**: ``https`` only. ``file://`` reads local files,
   ``git://`` is unauthenticated plaintext, ``ssh://`` would use the
   server's keys.
3. **Host allowlist** (``SPA_ALLOWED_GIT_HOSTS``), exact match after IDNA
   normalisation -- an allowlist cannot be bypassed by an encoding trick the
   way a denylist of "bad" addresses can. IP literals in any notation
   (``127.1``, ``2130706433``, ``0x7f000001``, ``[::1]``) are rejected outright.
4. **Resolution check** (defence in depth): every address the host resolves to
   must be globally routable; loopback, RFC 1918, link-local (including the
   169.254.169.254 cloud metadata endpoint), CGNAT, multicast and reserved
   ranges are refused. Resolution failure is a refusal (fail closed).

Residual risk, stated honestly: DNS can change between this check and git's own
lookup (rebinding). The host allowlist is what makes that impractical -- an
attacker would need to control DNS for github.com -- and git runs with
redirects disabled, so it cannot be bounced elsewhere.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LENGTH = 300
_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
# Integer, hex and short-dotted IPv4 notations that resolvers accept:
# 2130706433, 0x7f000001, 127.1, 0x7f.0.0.1
_NUMERIC_HOST = re.compile(r"^((0x[0-9a-f]+|\d+)\.?){1,4}$", re.IGNORECASE)

Resolver = Callable[[str], Iterable[str]]


class UnsafeRepositoryURL(ValueError):
    """The URL was refused. The message is safe to show to the user."""


@dataclass(frozen=True)
class ValidatedRepoURL:
    url: str        # normalised: https://<host>/<owner>/<repo>.git
    host: str
    path: str       # "<owner>/<repo>"


def system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                                 or ip.is_reserved or ip.is_unspecified)


def validate_repo_url(raw: str, allowed_hosts: Iterable[str], resolver: Resolver = system_resolver
                      ) -> ValidatedRepoURL:
    if not isinstance(raw, str) or not raw:
        raise UnsafeRepositoryURL("repository URL is required")
    if len(raw) > MAX_URL_LENGTH:
        raise UnsafeRepositoryURL("repository URL is too long")
    if raw != raw.strip() or any(ord(c) < 0x21 or ord(c) == 0x7F for c in raw):
        raise UnsafeRepositoryURL("repository URL contains whitespace or control characters")
    if raw.startswith("-"):
        raise UnsafeRepositoryURL("repository URL may not start with '-'")
    if "::" in raw.split("/", 1)[0] or re.match(r"^[\w.-]+@[\w.-]+:", raw):
        raise UnsafeRepositoryURL("git transport or scp-style syntax is not allowed; use https://")
    if "%" in raw or "\\" in raw:
        raise UnsafeRepositoryURL("percent-encoding and backslashes are not allowed in repository URLs")

    parts = urlsplit(raw)
    if parts.scheme.lower() != "https":
        raise UnsafeRepositoryURL("only https:// repository URLs are allowed")
    if "@" in parts.netloc or parts.username or parts.password:
        raise UnsafeRepositoryURL("credentials in repository URLs are not allowed")
    if parts.query or parts.fragment or "?" in raw or "#" in raw:
        raise UnsafeRepositoryURL("query strings and fragments are not allowed")
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeRepositoryURL("invalid port") from exc
    if port not in (None, 443):
        raise UnsafeRepositoryURL("only the default https port is allowed")

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeRepositoryURL("repository URL has no host")
    try:
        ipaddress.ip_address(host)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False
    # (Raising inside that try would be swallowed: UnsafeRepositoryURL is a ValueError.)
    if is_ip_literal or _NUMERIC_HOST.match(host):
        raise UnsafeRepositoryURL("IP-address hosts are not allowed")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsafeRepositoryURL("invalid host name") from exc
    allowed = {h.lower().rstrip(".") for h in allowed_hosts}
    if host not in allowed:
        raise UnsafeRepositoryURL(f"host {host!r} is not in the allowed list")

    segments = [s for s in parts.path.split("/") if s]
    if segments and segments[-1].endswith(".git"):
        segments[-1] = segments[-1][: -len(".git")]
    if not 2 <= len(segments) <= 4 or not all(_SEGMENT.match(s) and s not in {".", ".."} for s in segments):
        raise UnsafeRepositoryURL("repository path must look like /<owner>/<repo>")

    try:
        addresses = list(resolver(host))
    except (OSError, UnicodeError) as exc:
        raise UnsafeRepositoryURL(f"could not resolve {host}") from exc
    if not addresses:
        raise UnsafeRepositoryURL(f"could not resolve {host}")
    for address in addresses:
        try:
            public = _is_public(address)
        except ValueError as exc:
            raise UnsafeRepositoryURL("host resolved to an invalid address") from exc
        if not public:
            raise UnsafeRepositoryURL(f"{host} resolves to a non-public address")

    path = "/".join(segments)
    return ValidatedRepoURL(url=f"https://{host}/{path}.git", host=host, path=path)
