"""HTTPS to the server, with the developer's token -- and nowhere else.

* **No redirects are followed.** urllib would otherwise resend the request,
  ``Authorization`` header included, to wherever a redirect points. A server
  that redirects is reported instead, so the token never travels to an
  address the developer did not choose.
* **Certificates are always verified** (the system's trust store, or the
  ``SPA_CA_FILE`` bundle of an in-house authority); TLS 1.2 at least.
* **Every call has a timeout**, and a response may not exceed 16 MB.
* The token is sent only in the header, never in a URL, and is never printed.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode

from spa_connect import __version__
from spa_connect.errors import ApiError, ConnectError

DEFAULT_TIMEOUT_S = 60
SCAN_TIMEOUT_S = 15 * 60          # the server scans synchronously with four tools
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        raise ConnectError(f"the server answered with a redirect ({code}); refusing to send your token on. "
                           "Check the server address given to `spa connect`.")


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=os.environ.get("SPA_CA_FILE") or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _read_capped(stream) -> bytes:  # noqa: ANN001
    data = stream.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise ConnectError("the server's answer is too large")
    return data


def _detail(raw: bytes) -> str:
    try:
        detail = json.loads(raw.decode("utf-8")).get("detail", "")
    except (ValueError, AttributeError, UnicodeDecodeError):
        return raw.decode("utf-8", errors="replace")[:300] or "no details"
    if isinstance(detail, list):       # request validation errors
        return "; ".join(str(item.get("msg", item)) if isinstance(item, dict) else str(item) for item in detail)[:300]
    return str(detail)[:300] or "no details"


def multipart(field_name: str, filename: str, payload: bytes, content_type: str) -> tuple[bytes, str]:
    """One file as multipart/form-data (urllib has no encoder of its own)."""
    boundary = "spa-" + secrets.token_hex(16)
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {content_type}\r\n\r\n").encode("ascii")
    return head + payload + f"\r\n--{boundary}--\r\n".encode("ascii"), f"multipart/form-data; boundary={boundary}"


def path(*segments: object, **query: object) -> str:
    """``/api/v1/...`` with every segment escaped and an optional query string."""
    url = "/" + "/".join(quote(str(s), safe="") for s in segments)
    params = {k: v for k, v in query.items() if v is not None}
    return url + ("?" + urlencode(params) if params else "")


@dataclass
class Client:
    server: str                       # already normalised by urls.normalise_server
    token: str = field(repr=False)    # never shown, not even in a traceback's repr

    def __post_init__(self) -> None:
        self._opener = urllib.request.build_opener(_RefuseRedirects(),
                                                   urllib.request.HTTPSHandler(context=_tls_context()))

    def request(self, method: str, url_path: str, *, json_body: object = None, data: bytes | None = None,
                content_type: str | None = None, timeout: float = DEFAULT_TIMEOUT_S) -> object:
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json",
                   "User-Agent": f"spa-connect/{__version__}"}
        if json_body is not None:
            data, content_type = json.dumps(json_body).encode("utf-8"), "application/json"
        if data is not None:
            headers["Content-Type"] = content_type or "application/octet-stream"
        elif method in {"POST", "PUT", "PATCH"}:
            data = b""                # the server requires a Content-Length on every POST
        # The scheme was restricted to https (or http to this machine) by urls.normalise_server.
        request = urllib.request.Request(self.server + url_path, data=data, method=method,  # nosec B310
                                         headers=headers)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                raw = _read_capped(response)
        except urllib.error.HTTPError as exc:
            raise ApiError(exc.code, _detail(_read_capped(exc))) from None
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise ConnectError(f"the server's certificate could not be verified ({reason.verify_message}); "
                                   "if it uses an in-house authority, set SPA_CA_FILE") from None
            raise ConnectError(f"cannot reach {self.server}: {reason}") from None
        except (socket.timeout, TimeoutError):
            raise ConnectError(f"{self.server} did not answer within {int(timeout)} s") from None
        try:
            return json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            raise ConnectError("the server's answer is not valid JSON; is this a Secure Prompt Assistant "
                               "server?") from None

    def get(self, url_path: str, **kw: object) -> object:
        return self.request("GET", url_path, **kw)

    def post(self, url_path: str, **kw: object) -> object:
        return self.request("POST", url_path, **kw)
