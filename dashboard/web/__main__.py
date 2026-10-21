"""``python -m dashboard.web [--port N]`` -- serve the web interface on 127.0.0.1 only."""

from __future__ import annotations

import argparse

import uvicorn

from dashboard.web.app import create_web_app

# Not configurable: the interface reads local checkouts and must never be reachable from the network.
HOST = "127.0.0.1"
DEFAULT_PORT = 8080


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m dashboard.web", description="Serve the web interface (loopback).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port on 127.0.0.1 (default {DEFAULT_PORT})")
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    print(f"Secure Prompt Assistant: http://{HOST}:{args.port}  (Ctrl+C to stop)", flush=True)
    # proxy_headers off: nothing may claim, via X-Forwarded-For, to be a different client.
    uvicorn.run(create_web_app(), host=HOST, port=args.port, proxy_headers=False, server_header=False,
                date_header=False, log_level="warning")


if __name__ == "__main__":
    main()
