"""Per-email and per-IP limits on reset requests, stored as hashes only."""

from __future__ import annotations

from datetime import datetime, timedelta

import psycopg

from .db import SCHEMA, transaction
from .tokens import sha256_hex

WINDOW = timedelta(minutes=60)
EMAIL_LIMIT = 3
IP_LIMIT = 10


def allow(conn: psycopg.Connection, email: str, ip: str, now: datetime) -> bool:
    """Record this attempt and return whether it is within both limits.

    Every attempt is recorded, including refused ones. The decision counts the
    attempts in the last hour made before this one, so the 4th request for an
    address within an hour is refused and the 3 before it were allowed."""
    email_hash = sha256_hex(email.strip().lower())
    ip_hash = sha256_hex(ip.strip())
    since = now - WINDOW
    with transaction(conn):
        # Serialise concurrent attempts for the same email or IP. The transaction-scoped
        # advisory locks are taken in one fixed (sorted) order, so two bursts cannot
        # deadlock, and they are released at COMMIT. Without them, parallel requests all
        # count 0 before any insert commits and all pass the limit.
        for key in sorted([f"email:{email_hash}", f"ip:{ip_hash}"]):
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (key,))
        email_count = conn.execute(
            f"SELECT count(*) FROM {SCHEMA}.requests WHERE email_sha256 = %s AND created_at > %s",
            (email_hash, since),
        ).fetchone()[0]
        ip_count = conn.execute(
            f"SELECT count(*) FROM {SCHEMA}.requests WHERE ip_hash = %s AND created_at > %s",
            (ip_hash, since),
        ).fetchone()[0]
        conn.execute(
            f"INSERT INTO {SCHEMA}.requests (email_sha256, ip_hash, created_at) VALUES (%s, %s, %s)",
            (email_hash, ip_hash, now),
        )
    return email_count < EMAIL_LIMIT and ip_count < IP_LIMIT
