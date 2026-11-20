import pytest

from dograh_password_reset import guard
from dograh_password_reset.guard import GuardError, check_dograh

API = "http://api.example.test:8000"
HEALTH = API + "/api/v1/health"


def fake_get(responses):
    """Returns responses in order (the last one repeats); an Exception item is raised."""
    calls = []

    def get(url, timeout):
        calls.append(url)
        item = responses[min(len(calls), len(responses)) - 1]
        if isinstance(item, Exception):
            raise item
        return item

    get.calls = calls
    return get


def test_guard_rejects_non_local():
    get = fake_get([(200, {"auth_provider": "oidc", "version": "1.0"})])
    with pytest.raises(GuardError, match="local"):
        check_dograh(API, http_get=get, sleep=lambda s: None)
    assert get.calls == [HEALTH]


def test_guard_retries_then_fails():
    get = fake_get([OSError("connection refused"), (503, {}), OSError("refused")])
    sleeps = []
    with pytest.raises(GuardError):
        check_dograh(API, http_get=get, sleep=sleeps.append)
    assert len(get.calls) == 5
    assert sleeps == [3.0, 3.0, 3.0, 3.0]


def test_guard_returns_version():
    get = fake_get([(200, {"auth_provider": "local", "version": "1.2.3"})])
    assert check_dograh(API, http_get=get, sleep=lambda s: None) == "1.2.3"
    assert get.calls == [HEALTH]


def test_guard_succeeds_after_a_failed_try():
    get = fake_get([OSError("refused"), (200, {"auth_provider": "local", "version": "9"})])
    sleeps = []
    assert check_dograh(API, http_get=get, sleep=sleeps.append) == "9"
    assert sleeps == [3.0]


def test_startup_checks_schema_and_logs_version(ready_db, make_settings, monkeypatch, caplog):
    import logging

    monkeypatch.setattr(guard, "check_dograh", lambda api_url, *a, **k: "7.7.7")
    settings = make_settings()
    with caplog.at_level(logging.INFO):
        guard.startup(settings, ready_db)
    assert "dograh-password-reset ready (dograh 7.7.7)" in caplog.text
    tables = ready_db.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'password_reset'"
    ).fetchall()
    assert {row[0] for row in tables} == {"tokens", "requests"}
