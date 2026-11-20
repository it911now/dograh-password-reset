import logging
import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import bcrypt
import pytest
from fastapi.testclient import TestClient

from dograh_password_reset import guard, tokens
from dograh_password_reset.db import connect
from dograh_password_reset.guard import GuardError
from dograh_password_reset.mailer import MailError
from dograh_password_reset.web import create_app, make_lifespan

BASE = "https://dograh.example.test"
EMAIL = "user@example.test"
OLD_PW = "old password 123"
NEW_PW = "brand new password 456"
NEUTRAL = "If an account exists for that address, a link is on its way. It expires in 30 minutes."
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)


class FakeMailer:
    def __init__(self):
        self.sent = []
        self.fail = False

    def send(self, email):
        if self.fail:
            raise MailError("smtp send failed (SMTPException)")
        self.sent.append(email)


@pytest.fixture
def mailer():
    return FakeMailer()


@pytest.fixture
def settings(make_settings):
    return make_settings()


@pytest.fixture
def client(ready_db, settings, mailer):
    dsn = os.environ["TEST_DATABASE_URL"]
    app = create_app(settings, lambda: connect(dsn), mailer, lambda: NOW)
    return TestClient(app, base_url=BASE)


def csrf_from(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def post_request(client, email=EMAIL):
    page = client.get("/password-reset/")
    return client.post(
        "/password-reset/request", data={"email": email, "csrf": csrf_from(page.text)}
    )


def token_from_mail(mail):
    link = re.search(r"https://\S+/new\?token=[\w-]+", mail.text).group(0)
    return link, parse_qs(urlsplit(link).query)["token"][0]


def submit_new(client, token, pw=NEW_PW, confirm=None):
    page = client.get("/password-reset/new", params={"token": token})
    return client.post(
        "/password-reset/new",
        data={
            "token": token,
            "password": pw,
            "confirm": pw if confirm is None else confirm,
            "csrf": csrf_from(page.text),
        },
    )


def stored_hash(db, email=EMAIL):
    db.commit()
    return db.execute("SELECT password_hash FROM users WHERE email = %s", (email,)).fetchone()[0]


def test_request_known_and_unknown_identical(client, mailer, user):
    user(EMAIL, OLD_PW)
    known = post_request(client)
    assert len(mailer.sent) == 1
    link, _ = token_from_mail(mailer.sent[0])
    assert link.startswith(BASE + "/password-reset/new?token=")
    unknown = post_request(client, "nobody@example.test")
    assert len(mailer.sent) == 1
    assert known.status_code == unknown.status_code == 200
    assert known.content == unknown.content
    assert NEUTRAL in known.text


def test_request_rate_limited_sends_nothing(client, mailer, user):
    user(EMAIL, OLD_PW)
    pages = [post_request(client) for _ in range(4)]
    assert len(mailer.sent) == 3
    assert all(p.content == pages[0].content for p in pages)


def test_request_page_when_mailer_fails(client, mailer, user, caplog):
    user(EMAIL, OLD_PW)
    mailer.fail = True
    with caplog.at_level(logging.INFO):
        resp = post_request(client)
    assert resp.status_code == 200 and NEUTRAL in resp.text
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert EMAIL not in caplog.text
    assert "token=" not in caplog.text


@pytest.mark.parametrize(
    "bad", ["a\x00b@example.test", "a\nb@example.test", "x" * 321 + "@e.test", "   "]
)
def test_request_odd_emails_are_neutral_and_do_no_work(client, mailer, user, bad):
    user(EMAIL, OLD_PW)
    resp = post_request(client, bad)
    assert resp.status_code == 200 and NEUTRAL in resp.text
    assert mailer.sent == []


def test_lone_surrogate_email_is_unusable():
    from dograh_password_reset.web import _unusable_email

    assert _unusable_email("a\ud800@e.test") is True
    assert _unusable_email("ok@e.test") is False


def test_request_job_survives_any_exception(client, mailer, user, monkeypatch, caplog):
    user(EMAIL, OLD_PW)
    import dograh_password_reset.web as web

    def boom(*a, **k):
        raise RuntimeError("secret@example.test blew up")

    monkeypatch.setattr(web, "find_user", boom)
    with caplog.at_level(logging.INFO):
        resp = post_request(client)
    assert resp.status_code == 200 and NEUTRAL in resp.text
    assert "RuntimeError" in caplog.text
    assert "secret@example.test" not in caplog.text


def test_new_get_valid_and_invalid(client, mailer, user):
    user(EMAIL, OLD_PW)
    post_request(client)
    _, token = token_from_mail(mailer.sent[0])
    ok = client.get("/password-reset/new", params={"token": token})
    assert ok.status_code == 200 and 'name="password"' in ok.text
    bad = client.get("/password-reset/new", params={"token": "nope"})
    assert bad.status_code == 400
    assert 'href="/password-reset/"' in bad.text
    assert client.get("/password-reset/new").status_code == 400


def test_full_reset(client, mailer, user, ready_db):
    user(EMAIL, OLD_PW)
    post_request(client)
    _, token = token_from_mail(mailer.sent[0])
    resp = submit_new(client, token)
    assert resp.status_code == 200
    assert BASE + "/auth/login" in resp.text
    assert bcrypt.checkpw(NEW_PW.encode(), stored_hash(ready_db).encode())
    assert [m.kind for m in mailer.sent] == ["reset", "changed"]
    assert mailer.sent[1].to == EMAIL


def test_double_submit(client, mailer, user, ready_db):
    user(EMAIL, OLD_PW)
    post_request(client)
    _, token = token_from_mail(mailer.sent[0])
    page = client.get("/password-reset/new", params={"token": token})
    data = {"token": token, "password": NEW_PW, "confirm": NEW_PW, "csrf": csrf_from(page.text)}
    assert client.post("/password-reset/new", data=data).status_code == 200
    data["password"] = data["confirm"] = "a different password 789"
    second = client.post("/password-reset/new", data=data)
    assert second.status_code == 400
    assert "already been used" in second.text
    assert bcrypt.checkpw(NEW_PW.encode(), stored_hash(ready_db).encode())


@pytest.mark.parametrize(
    "pw,confirm,message",
    [
        ("short", "short", "Use at least 12 characters."),
        (EMAIL.upper(), EMAIL.upper(), "Don&#39;t use your email address as your password."),
        ("long enough pw 1", "long enough pw 2", "The two passwords don&#39;t match."),
    ],
)
def test_password_rules(client, mailer, user, ready_db, pw, confirm, message):
    user(EMAIL, OLD_PW)
    before = stored_hash(ready_db)
    post_request(client)
    _, token = token_from_mail(mailer.sent[0])
    resp = submit_new(client, token, pw, confirm)
    assert resp.status_code == 400
    assert message in resp.text
    assert stored_hash(ready_db) == before
    # the token survives a rejected attempt
    assert submit_new(client, token).status_code == 200


def test_multibyte_password_over_72_bytes(client, mailer, user, ready_db):
    user(EMAIL, OLD_PW)
    before = stored_hash(ready_db)
    post_request(client)
    _, token = token_from_mail(mailer.sent[0])
    pw = "€" * 25
    resp = submit_new(client, token, pw)
    assert resp.status_code == 400
    assert "Use at most 72 bytes (fewer if you use accents or symbols)." in resp.text
    assert stored_hash(ready_db) == before


def test_csrf_required(client, mailer, user):
    user(EMAIL, OLD_PW)
    page = client.get("/password-reset/")
    token = csrf_from(page.text)
    client.cookies.clear()
    assert client.post("/password-reset/request", data={"email": EMAIL, "csrf": token}).status_code == 403
    # cookie present but form value wrong
    client.get("/password-reset/")
    assert client.post("/password-reset/request", data={"email": EMAIL, "csrf": "wrong"}).status_code == 403
    assert client.post("/password-reset/new", data={"token": "x", "password": "p", "confirm": "p"}).status_code == 403
    assert mailer.sent == []


def test_headers_no_store_and_no_referrer(client):
    for path in ("/password-reset/", "/password-reset/new?token=zzz", "/password-reset/inject.js"):
        resp = client.get(path)
        assert resp.headers["cache-control"] == "no-store"
        assert resp.headers["referrer-policy"] == "no-referrer"
        assert resp.headers["x-frame-options"] == "DENY"


def test_logs_have_no_token_or_email(client, mailer, user, caplog):
    user(EMAIL, OLD_PW)
    with caplog.at_level(logging.DEBUG):
        post_request(client)
        _, token = token_from_mail(mailer.sent[0])
        submit_new(client, token)
    # httpx (the test client itself) logs request URLs; the app's own loggers must be clean.
    own = "\n".join(r.getMessage() for r in caplog.records if not r.name.startswith(("httpx", "httpcore")))
    assert token not in own
    assert EMAIL not in own


def test_access_log_filter_redacts_token():
    from dograh_password_reset.web import RedactTokenFilter

    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
        ("1.2.3.4:5", "GET", "/password-reset/new?token=SECRET_abc-1&x=2", "1.1", 200), None,
    )
    assert RedactTokenFilter().filter(record) is True
    assert "SECRET_abc-1" not in record.getMessage()
    assert "token=REDACTED&x=2" in record.getMessage()


def test_inject_js_served(client, settings):
    resp = client.get("/password-reset/inject.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]
    assert "dpr-forgot" in resp.text
    assert settings.dograh_login_path in resp.text


def test_request_form_and_healthz(client, settings):
    page = client.get("/password-reset/")
    assert page.status_code == 200 and settings.product_name in page.text
    health = client.get("/password-reset/healthz")
    assert health.status_code == 200 and health.text == "ok"


def test_request_returns_before_slow_send(ready_db, settings, user):
    events = []
    dsn = os.environ["TEST_DATABASE_URL"]

    class RecordingMailer:
        def send(self, email):
            events.append("mail-start")
            time.sleep(1.0)
            events.append("mail-done")

    app = create_app(settings, lambda: connect(dsn), RecordingMailer(), lambda: NOW)

    async def recording_app(scope, receive, send):
        async def tap(message):
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                events.append("response-complete")
            await send(message)

        await app(scope, receive, tap)

    client = TestClient(recording_app, base_url=BASE)
    user(EMAIL, OLD_PW)
    resp = post_request(client)
    assert resp.status_code == 200
    assert events.index("response-complete") < events.index("mail-start")


def test_unhandled_error_keeps_security_headers(settings, mailer, caplog):
    def broken():
        raise RuntimeError("token=SECRET_zzz leaked into an error")

    app = create_app(settings, broken, mailer, lambda: NOW)
    client = TestClient(app, base_url=BASE, raise_server_exceptions=False)
    with caplog.at_level(logging.INFO):
        resp = client.get("/password-reset/new", params={"token": "x"})
    assert resp.status_code == 500
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" in resp.headers
    assert "SECRET_zzz" not in resp.text
    assert "RuntimeError" in caplog.text
    assert "SECRET_zzz" not in caplog.text


def test_lifespan_refuses_to_start_when_guard_fails(ready_db, settings, mailer, monkeypatch):
    dsn = os.environ["TEST_DATABASE_URL"]

    def refuse(api_url, *args, **kwargs):
        raise GuardError("Dograh health check failed")

    monkeypatch.setattr(guard, "check_dograh", refuse)
    lifespan = make_lifespan(settings, lambda: connect(dsn), lambda: NOW)
    app = create_app(settings, lambda: connect(dsn), mailer, lambda: NOW, lifespan=lifespan)
    with pytest.raises(GuardError):
        with TestClient(app):
            pass


def test_purge_loop_runs_then_stops(ready_db, settings, mailer, monkeypatch):
    import dograh_password_reset.web as web

    dsn = os.environ["TEST_DATABASE_URL"]
    calls = []

    def fake_purge(conn, now):
        calls.append(now)
        return 0

    monkeypatch.setattr(guard, "check_dograh", lambda api_url, *a, **k: "test")
    monkeypatch.setattr(tokens, "purge", fake_purge)
    monkeypatch.setattr(web, "PURGE_INTERVAL_SECONDS", 0.01)
    lifespan = make_lifespan(settings, lambda: connect(dsn), lambda: NOW)
    app = create_app(settings, lambda: connect(dsn), mailer, lambda: NOW, lifespan=lifespan)
    with TestClient(app):
        deadline = time.monotonic() + 5
        while len(calls) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
    assert len(calls) >= 2
    stopped_at = len(calls)
    time.sleep(0.1)
    assert len(calls) == stopped_at  # cancelled on shutdown


class _Tracked:
    """Wraps a connection so the test can see how many are open at once."""

    def __init__(self, conn, state, lock):
        self._conn, self._state, self._lock = conn, state, lock

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def close(self):
        self._conn.close()
        with self._lock:
            self._state["open"] -= 1


def _tracked_factory(dsn, state, lock, hold=0.3):
    def factory():
        conn = connect(dsn)
        with lock:
            state["open"] += 1
            state["max"] = max(state["max"], state["open"])
        time.sleep(hold)  # keeps the slot busy so other requests have to queue or give up
        return _Tracked(conn, state, lock)

    return factory


def _run_threads(fn, count):
    import threading

    results = [None] * count

    def target(i):
        results[i] = fn(i)

    threads = [threading.Thread(target=target, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_db_use_is_bounded_and_excess_gets_503(ready_db, settings, mailer, monkeypatch):
    import threading
    from dataclasses import replace

    import dograh_password_reset.web as web

    monkeypatch.setattr(web, "DB_WAIT_SECONDS", 0.05)
    state, lock = {"open": 0, "max": 0}, threading.Lock()
    app = create_app(
        replace(settings, db_pool_size=2),
        _tracked_factory(os.environ["TEST_DATABASE_URL"], state, lock),
        mailer,
        lambda: NOW,
    )

    def hit(_i):
        c = TestClient(app, base_url=BASE, raise_server_exceptions=False)
        return c.get("/password-reset/new", params={"token": "x"})

    responses = _run_threads(hit, 8)
    assert state["max"] <= 2
    codes = sorted(r.status_code for r in responses)
    assert 503 in codes and 400 in codes
    busy = next(r for r in responses if r.status_code == 503)
    assert busy.headers["cache-control"] == "no-store"
    assert busy.headers["x-frame-options"] == "DENY"
    assert busy.headers["retry-after"] == "5"
    assert state["open"] == 0  # every connection was closed, slots all released


def test_request_stays_neutral_when_database_slots_are_exhausted(ready_db, settings, mailer, monkeypatch, caplog):
    import threading
    from dataclasses import replace

    import dograh_password_reset.web as web

    monkeypatch.setattr(web, "DB_WAIT_SECONDS", 0.05)
    state, lock = {"open": 0, "max": 0}, threading.Lock()
    app = create_app(
        replace(settings, db_pool_size=1),
        _tracked_factory(os.environ["TEST_DATABASE_URL"], state, lock),
        mailer,
        lambda: NOW,
    )

    def hit(i):
        c = TestClient(app, base_url=BASE)
        return post_request(c, f"nobody{i}@example.test")

    with caplog.at_level(logging.WARNING):
        responses = _run_threads(hit, 6)
    assert all(r.status_code == 200 and NEUTRAL in r.text for r in responses)
    assert len({r.content for r in responses}) == 1
    assert state["max"] <= 1
    assert "slots exhausted" in caplog.text
    assert "nobody" not in caplog.text


def test_scrub_filter_keeps_only_the_exception_class():
    import psycopg

    from dograh_password_reset.web import ScrubExceptionFilter

    try:
        raise psycopg.errors.UniqueViolation('duplicate key (email)=(victim@example.test) token=SECRET_q')
    except psycopg.Error:
        import sys

        record = logging.LogRecord("uvicorn.error", logging.ERROR, "", 0, "Exception in ASGI application\n", (), sys.exc_info())
    assert ScrubExceptionFilter().filter(record) is True
    text = logging.Formatter("%(message)s").format(record)
    assert "UniqueViolation" in text
    assert "victim@example.test" not in text and "SECRET_q" not in text and "Traceback" not in text


def test_scrub_filter_lets_startup_errors_through():
    import sys

    from dograh_password_reset.web import ScrubExceptionFilter

    try:
        raise GuardError("Dograh health check failed after 5 tries (HTTP 503).")
    except GuardError:
        record = logging.LogRecord("uvicorn.error", logging.ERROR, "", 0, "Exception in 'lifespan' protocol", (), sys.exc_info())
    ScrubExceptionFilter().filter(record)
    assert "Dograh health check failed" in logging.Formatter("%(message)s").format(record)


def test_uvicorn_error_log_is_scrubbed_end_to_end(settings, mailer):
    """The re-raised traceback uvicorn logs after our 500 handler must not carry the error text."""
    import io

    from dograh_password_reset.web import ScrubExceptionFilter

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("uvicorn.error")
    scrub = ScrubExceptionFilter()
    logger.addFilter(scrub)
    logger.addHandler(handler)
    try:
        def broken():
            raise RuntimeError("could not run for victim@example.test")

        app = create_app(settings, broken, mailer, lambda: NOW)
        client = TestClient(app, base_url=BASE, raise_server_exceptions=False)
        assert client.get("/password-reset/new", params={"token": "x"}).status_code == 500
        logger.error("Exception in ASGI application\n", exc_info=RuntimeError("could not run for victim@example.test"))
    finally:
        logger.removeFilter(scrub)
        logger.removeHandler(handler)
    out = stream.getvalue()
    assert "RuntimeError" in out
    assert "victim@example.test" not in out
