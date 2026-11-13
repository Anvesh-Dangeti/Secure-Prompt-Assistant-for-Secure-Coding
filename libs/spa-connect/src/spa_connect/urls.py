"""The server address: validated once, at ``spa connect``, and stored normalised.

* ``https://`` only, so the token and the code are encrypted in transit and the
  server's identity is checked against its certificate.
* ``http://`` is accepted for this machine only (127.0.0.1, localhost, ::1),
  for trying the tool locally; nothing leaves the machine then.
* No user name or password inside the address (they would be stored and
  logged as part of it), no query string, no fragment.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from spa_connect.errors import ConnectError

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def normalise_server(raw: str) -> str:
    text = (raw or "").strip()
    if not text or any(ch.isspace() for ch in text) or "\x00" in text:
        raise ConnectError("give the server address, e.g. https://spa.example.edu")
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in {"https", "http"}:
        raise ConnectError("the server address must start with https://")
    if "@" in parts.netloc:
        raise ConnectError("the server address must not contain a user name or password")
    if parts.query or parts.fragment:
        raise ConnectError("the server address must not contain '?' or '#'")
    host = (parts.hostname or "").lower()
    if not host:
        raise ConnectError("the server address has no host name")
    try:
        parts.port   # noqa: B018 -- raises ValueError for a malformed port
    except ValueError as exc:
        raise ConnectError("the server address has an invalid port") from exc
    if scheme == "http" and host not in LOOPBACK_HOSTS:
        raise ConnectError("plain http:// is only allowed for this machine (127.0.0.1); use https:// so your "
                           "token and code are encrypted on the way")
    return urlunsplit((scheme, parts.netloc.lower(), parts.path.rstrip("/"), "", ""))
