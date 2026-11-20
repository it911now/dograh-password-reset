from datetime import datetime, timedelta, timezone

from dograh_password_reset import ratelimit

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


def test_rate_limit_email(ready_db):
    for i in range(3):
        assert ratelimit.allow(ready_db, "user@example.com", f"10.0.0.{i}", NOW) is True
    # Case and surrounding spaces count as the same address.
    assert ratelimit.allow(ready_db, "  User@Example.com ", "10.0.0.9", NOW) is False
    assert ratelimit.allow(ready_db, "user@example.com", "10.0.0.10", NOW + timedelta(minutes=61)) is True
    stored = ready_db.execute("SELECT string_agg(row_to_json(r)::text, ' ') FROM password_reset.requests r").fetchone()[0]
    assert "user@example.com" not in stored
    assert "10.0.0.9" not in stored


def test_rate_limit_ip(ready_db):
    for i in range(10):
        assert ratelimit.allow(ready_db, f"person{i}@example.com", "203.0.113.7", NOW) is True
    assert ratelimit.allow(ready_db, "person10@example.com", "203.0.113.7", NOW) is False
    assert ratelimit.allow(ready_db, "person11@example.com", "198.51.100.1", NOW) is True


def test_concurrent_burst_same_email_allows_only_three(ready_db):
    """Six separate connections race on one email at the same instant. Without a lock
    all six count 0 before any insert commits and all six are allowed."""
    import os
    import threading

    import psycopg

    dsn = os.environ["TEST_DATABASE_URL"]
    workers = 6
    barrier = threading.Barrier(workers)
    results: list[bool] = []
    errors: list[BaseException] = []
    results_lock = threading.Lock()

    def attempt(index: int) -> None:
        conn = psycopg.connect(dsn, autocommit=False)
        try:
            barrier.wait(timeout=10)
            allowed = ratelimit.allow(conn, "burst@example.com", f"10.1.0.{index}", NOW)
            with results_lock:
                results.append(allowed)
        except BaseException as exc:  # surface thread failures in the main thread
            with results_lock:
                errors.append(exc)
        finally:
            conn.close()

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, errors
    assert len(results) == workers
    assert results.count(True) == 3
