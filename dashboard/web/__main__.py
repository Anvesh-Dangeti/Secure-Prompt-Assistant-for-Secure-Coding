"""``python -m dashboard.web [--port N]`` -- serve the web interface on 127.0.0.1 only."""

from __future__ import annotations

import argparse
import os
import threading

import uvicorn

from dashboard.web.app import create_web_app

# Not configurable: the interface reads local checkouts and must never be reachable from the network.
HOST = "127.0.0.1"
DEFAULT_PORT = 8080
# Ctrl+C waits at most this long for open browser connections before closing them.
SHUTDOWN_GRACE_S = 5


def _wait_for_running_work() -> None:
    """After the server stops: a scan still running in a worker thread keeps the process alive -- say so.

    A second Ctrl+C abandons it. The scanners got the same Ctrl+C from the console, and the database
    write is a transaction, so nothing half-written is kept.
    """
    busy = [t for t in threading.enumerate() if t is not threading.main_thread() and not t.daemon and t.is_alive()]
    if not busy:
        return
    print("Waiting for the running scan to finish before exiting (Ctrl+C again to stop now)...", flush=True)
    try:
        for thread in busy:
            while thread.is_alive():
                thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print("Stopped; the running scan was abandoned.", flush=True)
        os._exit(130)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m dashboard.web", description="Serve the web interface (loopback).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port on 127.0.0.1 (default {DEFAULT_PORT})")
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    print(f"Secure Prompt Assistant: http://{HOST}:{args.port}  (Ctrl+C to stop)", flush=True)
    try:
        uvicorn.run(
            create_web_app(), host=HOST, port=args.port,
            proxy_headers=False,            # nothing may claim, via X-Forwarded-For, to be a different client
            server_header=False, date_header=False,
            # The selector loop on Windows too: the default Proactor loop logs a ConnectionResetError whenever a
            # browser drops a connection. Scans run in worker threads, so no asyncio subprocess support is needed.
            loop="asyncio:SelectorEventLoop",
            timeout_graceful_shutdown=SHUTDOWN_GRACE_S,
            log_level="info", access_log=False,   # show start and stop; never log request paths
        )
    except KeyboardInterrupt:
        pass                                # uvicorn re-raises Ctrl+C after a clean shutdown
    _wait_for_running_work()
    print("Stopped.", flush=True)


if __name__ == "__main__":
    main()
