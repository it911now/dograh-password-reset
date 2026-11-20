"""Single-use reset tokens. Only the SHA-256 of a token is stored."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta

import psycopg

from .db import SCHEMA, transaction

USED_RETENTION = timedelta(hours=24)
REQUEST_RETENTION = timedelta(hours=2)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def issue(
    conn: psycopg.Connection, user_id: int, ttl_minutes: int, ip_hash: str, now: datetime
) -> str:
    """Create a token for the user and return the raw value. Older unused tokens of
    the same user are marked used, so only the newest link works."""
    raw = secrets.token_urlsafe(32)
    with transaction(conn):
        conn.execute(
            f"UPDATE {SCHEMA}.tokens SET used_at = %s WHERE user_id = %s AND used_at IS NULL",
            (now, user_id),
        )
        conn.execute(
            f"INSERT INTO {SCHEMA}.tokens"
            " (token_sha256, user_id, created_at, expires_at, used_at, request_ip_hash)"
            " VALUES (%s, %s, %s, %s, NULL, %s)",
            (sha256_hex(raw), user_id, now, now + timedelta(minutes=ttl_minutes), ip_hash),
        )
    return raw


def peek(conn: psycopg.Connection, raw: str, now: datetime) -> int | None:
    """Return the user id if the token is unused and unexpired, else None. Does not consume."""
    with transaction(conn):
        row = conn.execute(
            f"SELECT user_id FROM {SCHEMA}.tokens"
            " WHERE token_sha256 = %s AND used_at IS NULL AND expires_at > %s",
            (sha256_hex(raw), now),
        ).fetchone()
    return None if row is None else row[0]


def consume(conn: psycopg.Connection, raw: str, new_hash: str, now: datetime) -> bool:
    """Set the user's password hash and use up the token, in one transaction.
    Returns False (and changes nothing) if the token is unknown, used or expired."""
    with transaction(conn):
        row = conn.execute(
            f"SELECT user_id FROM {SCHEMA}.tokens"
            " WHERE token_sha256 = %s AND used_at IS NULL AND expires_at > %s FOR UPDATE",
            (sha256_hex(raw), now),
        ).fetchone()
        if row is None:
            return False
        user_id = row[0]
        updated = conn.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_id)
        )
        if updated.rowcount != 1:
            return False
        # Marks this token and any other unused token of the user as used.
        conn.execute(
            f"UPDATE {SCHEMA}.tokens SET used_at = %s WHERE user_id = %s AND used_at IS NULL",
            (now, user_id),
        )
        return True


def invalidate_user_tokens(conn: psycopg.Connection, user_id: int, now: datetime) -> None:
    """Mark every unused token of the user as used. The caller owns the transaction."""
    conn.execute(
        f"UPDATE {SCHEMA}.tokens SET used_at = %s WHERE user_id = %s AND used_at IS NULL",
        (now, user_id),
    )


def purge(conn: psycopg.Connection, now: datetime) -> int:
    """Delete expired tokens, tokens used more than 24 h ago and rate-limit rows older
    than 2 h. Returns the number of rows deleted."""
    with transaction(conn):
        tokens_removed = conn.execute(
            f"DELETE FROM {SCHEMA}.tokens WHERE expires_at < %s OR used_at < %s",
            (now, now - USED_RETENTION),
        ).rowcount
        requests_removed = conn.execute(
            f"DELETE FROM {SCHEMA}.requests WHERE created_at < %s", (now - REQUEST_RETENTION,)
        ).rowcount
    return tokens_removed + requests_removed
