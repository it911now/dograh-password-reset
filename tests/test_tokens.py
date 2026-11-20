from datetime import datetime, timedelta, timezone

import bcrypt

from dograh_password_reset import tokens

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


def _all_rows_text(conn):
    rows = conn.execute("SELECT row_to_json(t)::text FROM password_reset.tokens t").fetchall()
    return "\n".join(row[0] for row in rows)


def test_sha256_hex_known_vector():
    assert tokens.sha256_hex("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_token_stored_hashed(ready_db, user):
    uid = user("user@example.com", "old-password-123")
    raw = tokens.issue(ready_db, uid, 30, "ip-hash-1", NOW)
    ready_db.commit()
    assert len(raw) >= 43
    stored = ready_db.execute(
        "SELECT token_sha256 FROM password_reset.tokens WHERE user_id = %s", (uid,)
    ).fetchone()[0]
    assert stored == tokens.sha256_hex(raw)
    assert raw not in _all_rows_text(ready_db)


def test_peek_valid_then_expired(ready_db, user):
    uid = user("user@example.com", "old-password-123")
    raw = tokens.issue(ready_db, uid, 30, "ip-hash-1", NOW)
    ready_db.commit()
    assert tokens.peek(ready_db, raw, NOW) == uid
    assert tokens.peek(ready_db, raw, NOW + timedelta(minutes=29)) == uid
    assert tokens.peek(ready_db, raw, NOW + timedelta(minutes=31)) is None


def test_peek_unknown_token_is_none(ready_db, user):
    user("user@example.com", "old-password-123")
    assert tokens.peek(ready_db, "not-a-real-token", NOW) is None


def test_consume_sets_hash_once(ready_db, user):
    uid = user("user@example.com", "old-password-123")
    raw = tokens.issue(ready_db, uid, 30, "ip-hash-1", NOW)
    ready_db.commit()

    first = bcrypt.hashpw(b"first-new-password", bcrypt.gensalt(rounds=4)).decode("ascii")
    assert tokens.consume(ready_db, raw, first, NOW) is True
    stored = ready_db.execute("SELECT password_hash FROM users WHERE id = %s", (uid,)).fetchone()[0]
    assert bcrypt.checkpw(b"first-new-password", stored.encode("ascii"))

    second = bcrypt.hashpw(b"second-new-password", bcrypt.gensalt(rounds=4)).decode("ascii")
    assert tokens.consume(ready_db, raw, second, NOW) is False
    after = ready_db.execute("SELECT password_hash FROM users WHERE id = %s", (uid,)).fetchone()[0]
    assert after == stored


def test_consume_expired_is_false(ready_db, user):
    uid = user("user@example.com", "old-password-123")
    raw = tokens.issue(ready_db, uid, 30, "ip-hash-1", NOW)
    ready_db.commit()
    before = ready_db.execute("SELECT password_hash FROM users WHERE id = %s", (uid,)).fetchone()[0]
    late = NOW + timedelta(minutes=31)
    assert tokens.consume(ready_db, raw, "new-hash", late) is False
    after = ready_db.execute("SELECT password_hash FROM users WHERE id = %s", (uid,)).fetchone()[0]
    assert after == before


def test_older_token_dead_after_new_issue(ready_db, user):
    uid = user("user@example.com", "old-password-123")
    older = tokens.issue(ready_db, uid, 30, "ip-hash-1", NOW)
    newer = tokens.issue(ready_db, uid, 30, "ip-hash-2", NOW + timedelta(minutes=2))
    ready_db.commit()
    assert tokens.peek(ready_db, older, NOW + timedelta(minutes=3)) is None
    assert tokens.consume(ready_db, older, "hash-from-older", NOW + timedelta(minutes=3)) is False
    assert tokens.peek(ready_db, newer, NOW + timedelta(minutes=3)) == uid


def test_consume_invalidates_other_tokens(ready_db, user):
    uid = user("user@example.com", "old-password-123")
    raw = tokens.issue(ready_db, uid, 30, "ip-hash-1", NOW)
    # A second live token that issue() would normally have retired; insert it directly
    # so consume() is the code under test for invalidating the user's other tokens.
    ready_db.execute(
        "INSERT INTO password_reset.tokens (token_sha256, user_id, created_at, expires_at, request_ip_hash)"
        " VALUES (%s, %s, %s, %s, 'ip-hash-x')",
        ("b" * 64, uid, NOW, NOW + timedelta(minutes=30)),
    )
    ready_db.commit()
    assert tokens.consume(ready_db, raw, "new-hash", NOW + timedelta(minutes=1)) is True
    used_at = ready_db.execute(
        "SELECT used_at FROM password_reset.tokens WHERE token_sha256 = %s", ("b" * 64,)
    ).fetchone()[0]
    assert used_at is not None


def test_purge_removes_old_rows(ready_db, user):
    uid = user("user@example.com", "old-password-123")
    tok = (
        "INSERT INTO password_reset.tokens"
        " (token_sha256, user_id, created_at, expires_at, used_at, request_ip_hash)"
        " VALUES (%s, %s, %s, %s, %s, 'ip')"
    )
    # Expired and never used: removed.
    ready_db.execute(tok, ("1" * 64, uid, NOW - timedelta(hours=2), NOW - timedelta(hours=1), None))
    # Used more than 24 h ago: removed.
    ready_db.execute(
        tok,
        ("2" * 64, uid, NOW - timedelta(days=3), NOW - timedelta(days=2), NOW - timedelta(hours=25)),
    )
    # Used 1 h ago, still inside its TTL: kept.
    ready_db.execute(
        tok, ("3" * 64, uid, NOW - timedelta(hours=1), NOW + timedelta(minutes=10), NOW - timedelta(hours=1))
    )
    # Live and unused: kept.
    ready_db.execute(tok, ("4" * 64, uid, NOW, NOW + timedelta(minutes=10), None))
    req = "INSERT INTO password_reset.requests (email_sha256, ip_hash, created_at) VALUES ('e', 'i', %s)"
    ready_db.execute(req, (NOW - timedelta(hours=3),))  # removed
    ready_db.execute(req, (NOW - timedelta(hours=1),))  # kept
    ready_db.commit()

    removed = tokens.purge(ready_db, NOW)
    ready_db.commit()
    assert removed == 3
    remaining = {
        row[0] for row in ready_db.execute("SELECT token_sha256 FROM password_reset.tokens").fetchall()
    }
    assert remaining == {"3" * 64, "4" * 64}
    assert ready_db.execute("SELECT count(*) FROM password_reset.requests").fetchone()[0] == 1
