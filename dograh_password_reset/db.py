"""Postgres access: the Dograh `users` table (read/write password_hash) and the
add-on's own `password_reset` schema. Every function takes a time as `now`; nothing
here reads the clock."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

import psycopg

SCHEMA = "password_reset"
REQUIRED_USER_COLUMNS = frozenset({"id", "email", "password_hash"})


class SchemaError(Exception):
    """The Dograh users table does not have the columns this add-on needs."""


@dataclass
class User:
    id: int
    email: str
    password_hash: str | None = field(repr=False)


def connect(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn)


@contextmanager
def transaction(conn: psycopg.Connection) -> Iterator[psycopg.Connection]:
    """Commit on success, roll back on any exception. Works with autocommit off."""
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    conn.commit()


def ensure_schema(conn: psycopg.Connection) -> None:
    # The role needs no CREATE on the database when the schema already exists (an admin creates it
    # once, owned by this role: see examples/grants.sql). CREATE SCHEMA IF NOT EXISTS would still be
    # refused without that privilege even if the schema is there, so it is skipped in that case.
    with transaction(conn):
        schema_exists = conn.execute("SELECT to_regnamespace(%s) IS NOT NULL", (SCHEMA,)).fetchone()[0]
    statements = [] if schema_exists else [f"CREATE SCHEMA {SCHEMA}"]
    try:
        _create_objects(conn, statements)
    except psycopg.errors.InsufficientPrivilege:
        raise SchemaError(
            f"Schema {SCHEMA} is missing or not owned by this role, and the role may not create it. "
            f"An administrator must run: CREATE SCHEMA IF NOT EXISTS {SCHEMA} "
            "AUTHORIZATION <this role> (see examples/grants.sql)."
        ) from None


def _create_objects(conn: psycopg.Connection, statements: list[str]) -> None:
    statements = statements + [
        f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.tokens (
            token_sha256 text PRIMARY KEY,
            user_id int NOT NULL,
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL,
            used_at timestamptz NULL,
            request_ip_hash text
        )
        """,
        f"CREATE INDEX IF NOT EXISTS tokens_user_id_idx ON {SCHEMA}.tokens (user_id)",
        f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.requests (
            id bigserial PRIMARY KEY,
            email_sha256 text,
            ip_hash text,
            created_at timestamptz NOT NULL
        )
        """,
        f"CREATE INDEX IF NOT EXISTS requests_created_at_idx ON {SCHEMA}.requests (created_at)",
    ]
    with transaction(conn):
        for statement in statements:
            conn.execute(statement)


def check_users_table(conn: psycopg.Connection) -> None:
    with transaction(conn):
        rows = conn.execute(
            "SELECT column_name FROM information_schema.columns"
            " WHERE table_schema = 'public' AND table_name = 'users'"
        ).fetchall()
    present = {row[0] for row in rows}
    missing = sorted(REQUIRED_USER_COLUMNS - present)
    if missing:
        raise SchemaError("Dograh users table is missing columns: " + ", ".join(missing))


def find_user(conn: psycopg.Connection, email: str) -> User | None:
    with transaction(conn):
        row = conn.execute(
            "SELECT id, email, password_hash FROM users WHERE lower(email) = lower(%s)",
            (email.strip(),),
        ).fetchone()
    if row is None or row[2] is None:
        return None
    return User(id=row[0], email=row[1], password_hash=row[2])


def user_email(conn: psycopg.Connection, user_id: int) -> str | None:
    with transaction(conn):
        row = conn.execute("SELECT email FROM users WHERE id = %s", (user_id,)).fetchone()
    return None if row is None else row[0]
