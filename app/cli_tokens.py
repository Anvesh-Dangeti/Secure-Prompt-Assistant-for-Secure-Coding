"""Access-token administration for a shared server (registered by ``app.cli``).

    python -m app.cli token create --project helpdesk-portal --name rahul-laptop [--days 90]
    python -m app.cli token list
    python -m app.cli token revoke 3

Run on the server by its administrator. The token is printed once, by
``create``, and never again: only its hash is stored. Hand it to the developer
over a private channel; they paste it into ``spa connect``.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

from app.access_tokens import TokenError, create_token, list_tokens, revoke, state
from app.db.session import init_db, session_scope


def _date(moment: datetime | None) -> str:
    return moment.strftime("%Y-%m-%d %H:%M") if moment else "-"


def cmd_create(args: argparse.Namespace) -> int:
    init_db()
    try:
        with session_scope() as session:
            issued = create_token(session, args.project, args.name, args.days)
    except TokenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"\n  token #{issued.id} '{issued.name}' for project '{issued.project}' (id {issued.project_id}), "
          f"expires {_date(issued.expires_at)} UTC\n")
    print(f"  {issued.token}\n")
    print("  This is the only time the token is shown. Give it to the developer privately;")
    print("  they run `spa connect` in their project folder and paste it when asked.\n")
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    init_db()
    with session_scope() as session:
        rows = [[f"#{t.id}", f"{t.prefix}...", t.name, t.project.name, state(t), _date(t.created_at),
                 _date(t.expires_at), _date(t.last_used_at)] for t in list_tokens(session)]
    from app.cli import _table   # late import: app.cli registers this module

    print()
    print(_table(rows, ["ID", "TOKEN", "NAME", "PROJECT", "STATE", "CREATED", "EXPIRES", "LAST USED"]))
    print()
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    init_db()
    try:
        with session_scope() as session:
            row = revoke(session, args.token_id)
            print(f"  token #{row.id} '{row.name}' is revoked; it stops working on its next request.")
    except TokenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("token", help="per-developer access tokens for a shared server")
    tokens = p.add_subparsers(dest="token_command", required=True)
    c = tokens.add_parser("create", help="issue a token for one project (shown once)")
    c.add_argument("--project", required=True, help="the project the token may use (created if missing)")
    c.add_argument("--name", required=True, help="who or what holds it, e.g. rahul-laptop or ci")
    c.add_argument("--days", type=int, default=None, help="expiry in days (default 90)")
    c.set_defaults(func=cmd_create)
    tokens.add_parser("list", help="every token: prefix, owner, project, state").set_defaults(func=cmd_list)
    r = tokens.add_parser("revoke", help="withdraw a token at once")
    r.add_argument("token_id", type=int)
    r.set_defaults(func=cmd_revoke)
