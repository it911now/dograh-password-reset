import pytest

from dograh_password_reset import db as dbmod
from dograh_password_reset.db import SchemaError


def _tables(conn):
    rows = conn.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'password_reset'"
    ).fetchall()
    return {row[0] for row in rows}


def test_ensure_schema_twice_ok(db):
    dbmod.ensure_schema(db)
    dbmod.ensure_schema(db)
    db.commit()
    assert {"tokens", "requests"} <= _tables(db)


def test_ensure_schema_without_create_privilege_when_schema_exists(db):
    """The least-privilege role has no CREATE on the database: the schema is made for it by an admin."""
    import os
    from urllib.parse import urlsplit

    import psycopg

    dsn = os.environ["TEST_DATABASE_URL"]
    host, dbname = urlsplit(dsn).hostname, urlsplit(dsn).path.lstrip("/")
    db.execute("DROP ROLE IF EXISTS dpr_limited")
    db.execute("CREATE ROLE dpr_limited LOGIN PASSWORD 'limited-test-only'")
    db.execute(f'REVOKE CREATE ON DATABASE "{dbname}" FROM PUBLIC')
    db.execute("CREATE SCHEMA password_reset AUTHORIZATION dpr_limited")
    db.commit()
    try:
        limited = psycopg.connect(f"postgresql://dpr_limited:limited-test-only@{host}/{dbname}")
        try:
            dbmod.ensure_schema(limited)  # must not try CREATE SCHEMA
            dbmod.ensure_schema(limited)
            assert {"tokens", "requests"} <= _tables(limited)
        finally:
            limited.close()
        # Without the schema the same role cannot start: the error says what is missing.
        db.execute("DROP SCHEMA password_reset CASCADE")
        db.commit()
        limited = psycopg.connect(f"postgresql://dpr_limited:limited-test-only@{host}/{dbname}")
        try:
            with pytest.raises(SchemaError, match="AUTHORIZATION"):
                dbmod.ensure_schema(limited)
        finally:
            limited.close()
    finally:
        db.rollback()
        db.execute("DROP SCHEMA IF EXISTS password_reset CASCADE")
        db.execute("DROP ROLE IF EXISTS dpr_limited")
        db.execute(f'GRANT CREATE ON DATABASE "{dbname}" TO PUBLIC')
        db.commit()


def test_check_users_table_ok(db):
    dbmod.check_users_table(db)


def test_check_users_table_missing_column(db):
    db.execute("ALTER TABLE users DROP COLUMN password_hash")
    db.commit()
    with pytest.raises(SchemaError, match="password_hash"):
        dbmod.check_users_table(db)


def test_find_user_case_and_space(db, user):
    uid = user("User@Example.com", "old-password-123")
    found = dbmod.find_user(db, "  user@example.COM ")
    assert found is not None
    assert found.id == uid
    assert found.email == "User@Example.com"


def test_find_user_unknown_is_none(db, user):
    user("user@example.com", "old-password-123")
    assert dbmod.find_user(db, "nobody@example.com") is None


def test_find_user_null_hash_is_none(db):
    db.execute(
        "INSERT INTO users (provider_id, email, password_hash) VALUES ('p1', 'sso@example.com', NULL)"
    )
    db.commit()
    assert dbmod.find_user(db, "sso@example.com") is None
