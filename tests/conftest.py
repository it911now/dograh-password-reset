import os
import uuid
from pathlib import Path

import bcrypt
import psycopg
import pytest

from dograh_password_reset.db import ensure_schema

USERS_SQL = Path(__file__).with_name("dograh_users.sql")


@pytest.fixture
def db():
    """Fresh Postgres connection with the Dograh users table and no password_reset schema."""
    dsn = os.environ.get("TEST_DATABASE_URL")
    if not dsn:
        pytest.fail("TEST_DATABASE_URL is not set (run tests through run-tests.sh)")
    conn = psycopg.connect(dsn, autocommit=False)
    conn.execute("DROP SCHEMA IF EXISTS password_reset CASCADE")
    conn.execute("DROP TABLE IF EXISTS users CASCADE")
    conn.execute(USERS_SQL.read_text(encoding="utf-8"))
    conn.commit()
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def user(db):
    """Factory: user(email, password) inserts a Dograh-style local user and returns its id."""

    def add(email: str, password: str) -> int:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("ascii")
        row = db.execute(
            "INSERT INTO users (provider_id, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
            (uuid.uuid4().hex, email, hashed),
        ).fetchone()
        db.commit()
        return row[0]

    return add


@pytest.fixture
def ready_db(db):
    """The fresh db fixture with the password_reset schema created."""
    ensure_schema(db)
    db.commit()
    return db


@pytest.fixture
def make_settings(tmp_path):
    """Factory: make_settings(transport="webhook"|"smtp", **overrides) -> Settings with dummy values."""
    from dataclasses import replace

    from dograh_password_reset.config import load_settings

    def build(transport: str = "webhook", **overrides):
        db_file = tmp_path / "database_url"
        db_file.write_text("postgresql://test:test@localhost/test\n", encoding="utf-8")
        secret_file = tmp_path / "webhook_secret"
        secret_file.write_text("test-webhook-secret\n", encoding="utf-8")
        env = {
            "DATABASE_URL_FILE": str(db_file),
            "DOGRAH_API_URL": "http://api:8000",
            "PUBLIC_BASE_URL": "https://dograh.example.test",
            "MAIL_TRANSPORT": transport,
        }
        if transport == "smtp":
            env.update(SMTP_HOST="smtp.example.test", MAIL_FROM="noreply@example.test")
        else:
            env.update(
                MAIL_WEBHOOK_URL="https://hooks.example.test/reset",
                MAIL_WEBHOOK_SECRET_FILE=str(secret_file),
            )
        return replace(load_settings(env), **overrides)

    return build
