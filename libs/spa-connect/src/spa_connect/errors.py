"""Errors whose message is safe and useful to print as it is."""

from __future__ import annotations


class ConnectError(Exception):
    """Anything that stops a command: bad input, no connection, a refused request."""


class ApiError(ConnectError):
    """The server answered with an error status."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"server said {status}: {detail}")
        self.status = status
        self.detail = detail
