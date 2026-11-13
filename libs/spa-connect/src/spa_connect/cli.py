"""The ``spa`` command: connect a folder once, then scan, read findings, get prompts, verify fixes.

    spa connect --server https://spa.example.edu [--project NAME] [--token-stdin]
    spa status
    spa scan [--label TEXT]
    spa findings [--all | --state STATE]
    spa prompt ID [--strategy S7] [-o FILE]
    spa verify ID
    spa disconnect

Exit codes: 0 done (verify: VERIFIED_RESOLVED), 1 the scan or the fix did not
pass, 2 a usage or connection problem.

The token is read from a hidden prompt or from standard input, never from the
command line, where it would be kept in the shell's history and be visible in
the process list.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import tempfile
from pathlib import Path, PurePosixPath

from spa_connect import __version__
from spa_connect.config import (
    Link, credentials_path, find_link, forget_token, load_token, remove_link, save_token, valid_token, write_link,
)
from spa_connect.errors import ApiError, ConnectError
from spa_connect.pack import pack
from spa_connect.transport import SCAN_TIMEOUT_S, Client, multipart, path
from spa_connect.urls import normalise_server

OPEN_STATES = ("NEW", "STILL_OPEN", "REGRESSION")
MAX_PROMPT_SOURCE_BYTES = 1024 * 1024          # the server's SPA_MAX_CONTEXT_FILE_BYTES default


def _err(message: str) -> None:
    print(f"spa: {message}", file=sys.stderr)


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)), "  ".join("-" * w for w in widths)]
    return "\n".join(lines + ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)) for r in rows])


def _folder(args: argparse.Namespace) -> Path:
    folder = Path(args.dir).expanduser().resolve()
    if not folder.is_dir():
        raise ConnectError(f"not a folder: {folder}")
    return folder


def _connection(args: argparse.Namespace) -> tuple[Link, Client]:
    link = find_link(_folder(args))
    if link is None:
        raise ConnectError("this folder is not connected; run `spa connect --server <address>` in it first")
    token = load_token(link.server, link.project)
    if not token:
        raise ConnectError(f"no token stored for {link.project} on {link.server}; run `spa connect` again")
    return link, Client(link.server, token)


def _stdin_line() -> str:
    # Windows PowerShell pipes text with a UTF-8 byte-order mark when $OutputEncoding is UTF-8;
    # reading bytes and decoding as utf-8-sig drops it whatever the console code page is.
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is not None:
        return buffer.readline().decode("utf-8-sig", errors="replace")
    return sys.stdin.readline().lstrip("﻿")


def _read_token(from_stdin: bool) -> str:
    if from_stdin:
        token = _stdin_line().strip()
    else:
        token = getpass.getpass("Access token from your administrator (input hidden): ").strip()
    if not valid_token(token):
        raise ConnectError("that is not an access token (they start with spa_pat_); ask your administrator for one")
    return token


# ---- commands --------------------------------------------------------------------------------------


def cmd_connect(args: argparse.Namespace) -> int:
    folder = _folder(args)
    server = normalise_server(args.server)
    token = _read_token(args.token_stdin)
    who = Client(server, token).get(path("api", "v1", "whoami"))
    if not isinstance(who, dict) or who.get("kind") != "token":
        raise ConnectError("the server did not accept this as a developer access token")
    project = str(who["project"])
    if args.project and args.project != project:
        raise ConnectError(f"this token is for project '{project}', not '{args.project}'")
    save_token(server, project, token)
    write_link(folder, server, project, int(who["project_id"]))
    print(f"Connected {folder}")
    print(f"  to project '{project}' on {server}")
    print(f"  token '{who.get('token_name')}', expires {str(who.get('expires_at', '-'))[:10]}; "
          f"stored in {credentials_path()}")
    print("Next: spa scan")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    link, client = _connection(args)
    who = client.get(path("api", "v1", "whoami"))
    print(f"{link.root} -> project '{link.project}' (id {link.project_id}) on {link.server}")
    print(f"  token '{who.get('token_name')}', expires {str(who.get('expires_at', '-'))[:10]}")
    return 0


def _scan(link: Link, client: Client, label: str | None) -> dict:
    with tempfile.TemporaryDirectory(prefix="spa-upload-") as work:
        packed = pack(link.root, Path(work) / "upload.zip")
        if packed.skipped_secrets:
            print(f"  not sent (local secret files): {', '.join(packed.skipped_secrets[:5])}")
        if packed.skipped_links:
            print(f"  not sent (links): {len(packed.skipped_links)}")
        size = packed.archive.stat().st_size
        print(f"Uploading {packed.files} files ({size / 1024:.0f} KB) to {link.server} and scanning ...", flush=True)
        body, content_type = multipart("archive", "upload.zip", packed.archive.read_bytes(), "application/zip")
    summary = client.post(path("api", "v1", "projects", link.project_id, "scans", "zip", label=label or None),
                          data=body, content_type=content_type, timeout=SCAN_TIMEOUT_S)
    if not isinstance(summary, dict):
        raise ConnectError("unexpected answer from the server")
    return summary


def _print_summary(summary: dict) -> None:
    print(f"\n  scan #{summary.get('scan_id')}  status {summary.get('status')}")
    if summary.get("error"):
        print(f"  error: {summary['error']}")
    scanners = summary.get("scanners") or {}
    if scanners:
        print("  scanners: " + ", ".join(f"{k} {v}" for k, v in scanners.items()))
        print(f"  findings: {summary.get('findings')}")
    lifecycle = {k: v for k, v in (summary.get("lifecycle") or {}).items() if v}
    if lifecycle:
        print("  changes:  " + ", ".join(f"{k} {v}" for k, v in lifecycle.items()))
    print()


def cmd_scan(args: argparse.Namespace) -> int:
    link, client = _connection(args)
    summary = _scan(link, client, args.label)
    _print_summary(summary)
    print("Next: spa findings")
    return 0 if summary.get("status") == "COMPLETED" else 1


def cmd_findings(args: argparse.Namespace) -> int:
    link, client = _connection(args)
    state = args.state.upper() if args.state else None
    rows = client.get(path("api", "v1", "projects", link.project_id, "findings", state=state))
    if not isinstance(rows, list):
        raise ConnectError("unexpected answer from the server")
    if not args.all and state is None:
        rows = [r for r in rows if r.get("status") in OPEN_STATES]
    table = [[str(r["id"]), r["status"], r["severity"], r.get("cwe") or "-",
              f"{r['file_path']}:{r.get('start_line') or '-'}", str(r["rule_id"]).split(".")[-1][:34]] for r in rows]
    print()
    print(_table(table, ["ID", "STATE", "SEV", "CWE", "LOCATION", "RULE"]))
    print(f"\n  {len(rows)} finding(s){'' if args.all or state else ' open (--all shows every state)'}")
    if rows:
        print("  Next: spa prompt <ID>")
    print()
    return 0


def _within(child: Path, parent: Path) -> bool:
    child_c, parent_c = os.path.normcase(os.fspath(child)), os.path.normcase(os.fspath(parent))
    try:
        return os.path.commonpath([child_c, parent_c]) == parent_c
    except ValueError:            # different drives on Windows
        return False


def _local_file(link: Link, rel: str) -> Path:
    """The finding's file in this folder -- refused if the server's path would lead outside it."""
    pure = PurePosixPath(rel)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ConnectError(f"refusing an unexpected file path from the server: {rel!r}")
    candidate = link.root.joinpath(*pure.parts)
    if not _within(candidate.resolve(), link.root.resolve()):
        raise ConnectError(f"{rel} leads outside this project; refusing to read it")
    if candidate.is_symlink() or not candidate.is_file():
        raise ConnectError(f"{rel} is not a regular file in {link.root}; has it been moved or deleted?")
    if candidate.stat().st_size > MAX_PROMPT_SOURCE_BYTES:
        raise ConnectError(f"{rel} is larger than 1 MB; the server will not build a prompt from it")
    return candidate


def cmd_prompt(args: argparse.Namespace) -> int:
    link, client = _connection(args)
    tracked = client.get(path("api", "v1", "tracked", args.finding))
    rel = str(tracked["file_path"])
    content = _local_file(link, rel).read_bytes().decode("utf-8", errors="replace")
    # Only this one file is sent -- the server needs the flagged lines and their function, nothing more.
    result = client.post(path("api", "v1", "tracked", args.finding, "prompt"),
                         json_body={"strategy": args.strategy, "file_path": rel, "content": content})
    lint = result.get("lint") or {}
    if args.out:
        Path(args.out).write_text(result["prompt"] + "\n", encoding="utf-8")
        print(f"prompt written to {args.out}", file=sys.stderr)
    else:
        print(result["prompt"])
    print(f"\n[{result['strategy']}] lint {'PASS' if lint.get('passed') else 'FAIL'}, ~{result['tokens']} tokens. "
          f"Paste it into your coding assistant, apply the fix, then: spa verify {args.finding}", file=sys.stderr)
    if result.get("warning"):
        print(f"warning: {result['warning']}", file=sys.stderr)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    link, client = _connection(args)
    summary = _scan(link, client, args.label or f"verify #{args.finding}")
    _print_summary(summary)
    if summary.get("status") == "FAILED":
        _err("the scan failed, so the fix cannot be judged")
        return 1
    result = client.post(path("api", "v1", "tracked", args.finding, "verify", scan_id=summary["scan_id"]))
    print(f"  finding #{args.finding}: {result['verdict']}")
    if result.get("reason"):
        print(f"  {result['reason']}")
    for gate in result.get("gates") or []:
        print(f"    {gate['status']:<10} {gate['title']}: {gate['detail']}")
    print()
    return 0 if result["verdict"] == "VERIFIED_RESOLVED" else 1


def cmd_disconnect(args: argparse.Namespace) -> int:
    link = find_link(_folder(args))
    if link is None:
        print("this folder is not connected")
        return 0
    forgotten = forget_token(link.server, link.project)
    remove_link(link.root)
    print(f"Disconnected {link.root}{'' if forgotten else ' (no stored token was found)'}")
    return 0


# ---- parser ------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spa", description="Connect this project folder to a Secure Prompt "
                                     "Assistant server: scan, get remediation prompts, verify fixes.")
    parser.add_argument("--version", action="version", version=f"spa-connect {__version__}")
    parser.add_argument("--dir", default=".", help="the project folder (default: the current folder)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("connect", help="connect this folder to a server with your access token")
    p.add_argument("--server", required=True, help="e.g. https://spa.example.edu")
    p.add_argument("--project", help="check that the token is for this project")
    p.add_argument("--token-stdin", action="store_true", help="read the token from standard input (scripts, CI)")
    p.set_defaults(func=cmd_connect)
    sub.add_parser("status", help="show the connection and check the token").set_defaults(func=cmd_status)
    p = sub.add_parser("scan", help="upload this folder and scan it on the server")
    p.add_argument("--label", help="a note for this scan, e.g. 'before the fix'")
    p.set_defaults(func=cmd_scan)
    p = sub.add_parser("findings", help="the project's findings (open ones by default)")
    p.add_argument("--state", choices=["new", "still_open", "resolved", "regression", "suppressed"])
    p.add_argument("--all", action="store_true", help="every state, including resolved and suppressed")
    p.set_defaults(func=cmd_findings)
    p = sub.add_parser("prompt", help="a remediation prompt for one finding, to paste into your coding assistant")
    p.add_argument("finding", type=int, help="the finding's ID (see `spa findings`)")
    p.add_argument("--strategy", default="S7", help="prompt strategy: S7 (default), S7a, S7m, S0-S8")
    p.add_argument("-o", "--out", help="write the prompt to this file instead of the screen")
    p.set_defaults(func=cmd_prompt)
    p = sub.add_parser("verify", help="rescan this folder and judge the fix (checks 1, 2, 3a)")
    p.add_argument("finding", type=int)
    p.add_argument("--label", help="a note for the new scan")
    p.set_defaults(func=cmd_verify)
    sub.add_parser("disconnect", help="forget the token and the link for this folder").set_defaults(
        func=cmd_disconnect)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")   # a prompt must print even on a legacy console code page
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ApiError as exc:
        if exc.status == 401:
            _err("the server refused the token (expired or revoked?). Ask your administrator for a new one and "
                 "run `spa connect` again.")
        else:
            _err(exc.detail if exc.status in (400, 404, 409, 413, 422) else str(exc))
        return 2
    except ConnectError as exc:
        _err(str(exc))
        return 2
    except KeyboardInterrupt:
        _err("interrupted")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
