"""The token only goes where it was told to; the command line never takes it; server paths stay in the project."""

from __future__ import annotations

import io
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from spa_connect import cli, transport
from spa_connect.config import Link
from spa_connect.errors import ApiError, ConnectError
from spa_connect.transport import Client, multipart, path

TOKEN = "spa_pat_" + "A" * 43


class _Handler(BaseHTTPRequestHandler):
    seen: list[dict] = []

    def log_message(self, *_args: object) -> None:   # keep test output quiet
        pass

    def _send(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {"Content-Type": "application/json"}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.seen.append({"path": self.path, "auth": self.headers.get("Authorization"),
                          "length": self.headers.get("Content-Length"), "body": body})
        port = self.server.server_address[1]
        routes = {
            "/redirect": (302, b"", {"Location": f"http://127.0.0.1:{port}/landing"}),
            "/error": (404, json.dumps({"detail": "nope"}).encode(), None),
            "/invalid": (422, json.dumps({"detail": [{"msg": "Field required"}]}).encode(), None),
            "/text": (200, b"<html>hello</html>", {"Content-Type": "text/html"}),
            "/big": (200, b"[" + b"1," * 600 + b"1]", None),
        }
        status, payload, headers = routes.get(self.path.split("?")[0], (200, json.dumps({"ok": True}).encode(), None))
        self._send(status, payload, headers)

    do_GET = do_POST = _handle


@pytest.fixture
def server() -> Iterator[str]:
    _Handler.seen = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_the_token_travels_in_the_header_only(server: str) -> None:
    assert Client(server, TOKEN).post("/echo", json_body={"a": 1}) == {"ok": True}
    request = _Handler.seen[-1]
    assert request["auth"] == f"Bearer {TOKEN}" and TOKEN not in request["path"]
    assert json.loads(request["body"]) == {"a": 1}


def test_an_empty_post_still_declares_its_length(server: str) -> None:
    Client(server, TOKEN).post("/echo")
    assert _Handler.seen[-1]["length"] == "0"


def test_redirects_are_refused_and_the_token_is_not_resent(server: str) -> None:
    with pytest.raises(ConnectError, match="redirect"):
        Client(server, TOKEN).get("/redirect")
    assert [r["path"] for r in _Handler.seen] == ["/redirect"]          # /landing was never requested


def test_server_errors_carry_their_detail(server: str) -> None:
    with pytest.raises(ApiError) as caught:
        Client(server, TOKEN).get("/error")
    assert caught.value.status == 404 and caught.value.detail == "nope"
    with pytest.raises(ApiError, match="Field required"):
        Client(server, TOKEN).get("/invalid")


def test_unexpected_or_oversized_answers_are_refused(server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConnectError, match="not valid JSON"):
        Client(server, TOKEN).get("/text")
    monkeypatch.setattr(transport, "MAX_RESPONSE_BYTES", 100)
    with pytest.raises(ConnectError, match="too large"):
        Client(server, TOKEN).get("/big")


def test_an_unreachable_server_is_reported() -> None:
    with pytest.raises(ConnectError, match="cannot reach"):
        Client("http://127.0.0.1:9", TOKEN).get("/x", timeout=5)


def test_the_token_is_not_in_the_clients_repr() -> None:
    assert TOKEN not in repr(Client("https://spa.example.edu", TOKEN))


def test_paths_escape_every_segment_and_skip_empty_query_values() -> None:
    assert path("api", "v1", "tracked", 5, "verify", scan_id=7) == "/api/v1/tracked/5/verify?scan_id=7"
    assert path("api", "x/../y", label=None) == "/api/x%2F..%2Fy"
    assert path("p", label="before fix") == "/p?label=before+fix"


def test_multipart_framing() -> None:
    body, content_type = multipart("archive", "upload.zip", b"PK\x03\x04", "application/zip")
    boundary = content_type.split("boundary=")[1]
    assert body.startswith(f"--{boundary}\r\n".encode()) and body.endswith(f"\r\n--{boundary}--\r\n".encode())
    assert b'name="archive"; filename="upload.zip"' in body and b"PK\x03\x04" in body


# ---- the command line -------------------------------------------------------------------------------


def _options(parser) -> list[str]:  # noqa: ANN001
    found = [s for action in parser._actions for s in action.option_strings]
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):               # sub-commands
            found += [o for sub in choices.values() for o in _options(sub)]
    return found


def test_no_command_takes_a_token_argument() -> None:
    assert [o for o in _options(cli.build_parser()) if "token" in o] == ["--token-stdin"]


def test_a_malformed_token_is_refused_before_anything_is_sent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                              capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("not-a-token\n"))
    code = cli.main(["--dir", str(tmp_path), "connect", "--server", "https://spa.example.edu", "--token-stdin"])
    assert code == 2 and "spa_pat_" in capsys.readouterr().err


@pytest.mark.parametrize("stdin", [
    io.TextIOWrapper(io.BytesIO(b"\xef\xbb\xbf" + TOKEN.encode() + b"\r\n"), encoding="cp1252"),  # PowerShell pipe
    io.StringIO("﻿" + TOKEN + "\n"),
    io.StringIO(TOKEN + "\n"),
])
def test_a_piped_token_survives_a_byte_order_mark(stdin: io.TextIOBase, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", stdin)
    assert cli._read_token(from_stdin=True) == TOKEN


def test_commands_need_a_connected_folder(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for command in (["scan"], ["findings"], ["prompt", "1"], ["verify", "1"], ["status"]):
        assert cli.main(["--dir", str(tmp_path), *command]) == 2
        assert "not connected" in capsys.readouterr().err


def test_plain_http_to_another_machine_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--dir", str(tmp_path), "connect", "--server", "http://spa.example.edu"]) == 2
    assert "https://" in capsys.readouterr().err


def test_server_paths_cannot_lead_outside_the_project(tmp_path: Path) -> None:
    root = tmp_path / "p"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "outside.py").write_text("secret\n", encoding="utf-8")
    link = Link(root, "https://spa.example.edu", "p", 1)
    assert cli._local_file(link, "pkg/app.py") == root / "pkg" / "app.py"
    for bad in ("../outside.py", "/etc/passwd", "pkg/../../outside.py", "", "missing.py", "pkg"):
        with pytest.raises(ConnectError):
            cli._local_file(link, bad)
    try:
        (root / "link.py").symlink_to(tmp_path / "outside.py")
    except (OSError, NotImplementedError):
        return
    with pytest.raises(ConnectError, match="outside|not a regular"):
        cli._local_file(link, "link.py")
