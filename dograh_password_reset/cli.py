"""Admin command, run inside the add-on container:

    dograh-reset set-password EMAIL      new password read from stdin (one trailing newline dropped)
    dograh-reset generate-link EMAIL     print a single-use reset link (valid for the usual TTL)

Nothing secret is printed except the link that generate-link exists to print.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import datetime, timezone

import psycopg

from . import passwords, tokens
from .config import ConfigError, Settings, load_settings
from .db import connect, ensure_schema, find_user, transaction
from .tokens import sha256_hex

NO_ACCOUNT = "No account with that email."


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _set_password(conn: psycopg.Connection, email: str) -> int:
    user = find_user(conn, email)
    if user is None:
        print(NO_ACCOUNT)
        return 1
    password = sys.stdin.read()
    if password.endswith("\n"):
        password = password[:-1]
    errors = passwords.validate(password, password, user.email)
    if errors:
        for message in errors:
            print(message)
        return 1
    new_hash = passwords.hash(password)
    with transaction(conn):
        conn.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user.id))
        tokens.invalidate_user_tokens(conn, user.id, _now())
    print("Password updated.")
    return 0


def _generate_link(conn: psycopg.Connection, settings: Settings, email: str) -> int:
    user = find_user(conn, email)
    if user is None:
        print(NO_ACCOUNT)
        return 1
    raw = tokens.issue(conn, user.id, settings.ttl_minutes, sha256_hex("cli"), _now())
    base = settings.base_path.rstrip("/")
    print(f"{settings.public_base_url}{base}/new?token={raw}")
    print(f"It expires in {settings.ttl_minutes} minutes and works once.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dograh-reset", description="Dograh password-reset admin commands.")
    commands = parser.add_subparsers(dest="command", required=True)
    set_pw = commands.add_parser("set-password", help="set a user's password (new password on stdin)")
    set_pw.add_argument("email")
    link = commands.add_parser("generate-link", help="print a single-use reset link for a user")
    link.add_argument("email")
    args = parser.parse_args(argv)

    try:
        settings = load_settings(os.environ)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    try:
        conn = connect(settings.database_url)
    except psycopg.Error as exc:
        print(f"Database error ({type(exc).__name__}).", file=sys.stderr)
        return 1
    try:
        ensure_schema(conn)
        if args.command == "set-password":
            return _set_password(conn, args.email)
        return _generate_link(conn, settings, args.email)
    except psycopg.Error as exc:
        print(f"Database error ({type(exc).__name__}).", file=sys.stderr)
        return 1
    finally:
        conn.close()
