import hashlib
import hmac
import json
import logging
import socket
from email import policy
from email.parser import BytesParser

import httpx
import pytest
from aiosmtpd.controller import Controller

from dograh_password_reset import mailer, messages
from dograh_password_reset.mailer import MailError, SmtpMailer, WebhookMailer

LINK = "https://dograh.example.test/password-reset/new?token=TOKEN-SECRET-VALUE"
TO = "user@example.test"


def _email(settings):
    return messages.reset_email(settings, TO, LINK)


def test_sign_known_vector():
    # Precomputed: printf '{"a":1}' | openssl dgst -sha256 -hmac s
    assert mailer.sign(b'{"a":1}', "s") == (
        "sha256=37beaf650f70b40ec9706929c2e9d835cbd63729988f48781e6383a147215f07"
    )


def test_webhook_posts_signed_json(make_settings):
    settings = make_settings("webhook")
    email = _email(settings)
    calls = []

    def fake_post(url, content, headers, timeout):
        calls.append((url, content, headers, timeout))
        return 204

    WebhookMailer(settings, http_post=fake_post).send(email)

    assert len(calls) == 1
    url, body, headers, timeout = calls[0]
    assert url == settings.mail_webhook_url
    assert timeout == 10
    assert headers["Content-Type"] == "application/json"
    assert headers["X-Dograh-Reset-Signature"].startswith("sha256=")
    expected_sig = hmac.new(b"test-webhook-secret", body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(headers["X-Dograh-Reset-Signature"], f"sha256={expected_sig}")
    assert json.loads(body) == {
        "to": email.to,
        "subject": email.subject,
        "text": email.text,
        "html": email.html,
        "kind": "reset",
    }


def test_webhook_non_2xx_raises(make_settings):
    settings = make_settings("webhook")
    with pytest.raises(MailError):
        WebhookMailer(settings, http_post=lambda *a, **k: 500).send(_email(settings))


def test_webhook_transport_error_is_mail_error(make_settings):
    settings = make_settings("webhook")

    def refused(*args, **kwargs):
        raise OSError("connection refused")

    with pytest.raises(MailError):
        WebhookMailer(settings, http_post=refused).send(_email(settings))


def test_default_webhook_post_uses_httpx(make_settings, monkeypatch):
    settings = make_settings("webhook")
    seen = {}

    def fake_httpx_post(url, content, headers, timeout):
        seen.update(url=url, headers=headers, timeout=timeout)
        return httpx.Response(204)

    def fake_post(url, **kw):
        return fake_httpx_post(url, kw["content"], kw["headers"], kw["timeout"])

    monkeypatch.setattr(httpx, "post", fake_post)
    WebhookMailer(settings).send(_email(settings))
    assert seen["url"] == settings.mail_webhook_url
    assert seen["timeout"] == 10


class _Collector:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(envelope.content)
        return "250 OK"


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_smtp_sends_via_local_server(make_settings):
    handler = _Collector()
    port = _free_port()
    controller = Controller(handler, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        settings = make_settings(
            "smtp",
            smtp_host="127.0.0.1",
            smtp_port=port,
            smtp_starttls=False,
            smtp_username=None,
            smtp_password=None,
        )
        email = _email(settings)
        SmtpMailer(settings).send(email)
    finally:
        controller.stop()

    assert len(handler.messages) == 1
    msg = BytesParser(policy=policy.default).parsebytes(handler.messages[0])
    assert msg["From"] == "noreply@example.test"
    assert msg["To"] == TO
    assert msg["Subject"] == email.subject
    plain = msg.get_body(preferencelist=("plain",)).get_content()
    html = msg.get_body(preferencelist=("html",)).get_content()
    assert LINK in plain
    assert LINK in html


def test_smtp_connection_refused_is_mail_error(make_settings):
    settings = make_settings("smtp", smtp_host="127.0.0.1", smtp_port=_free_port(), smtp_starttls=False)
    with pytest.raises(MailError):
        SmtpMailer(settings).send(_email(settings))


class _Raising:
    def send(self, email):
        raise MailError(f"smtp send failed to {email.to}")


def test_send_failure_is_quiet(make_settings, caplog):
    settings = make_settings("webhook")
    email = _email(settings)
    with caplog.at_level(logging.DEBUG):
        ok = mailer.send_quietly(_Raising(), email, logging.getLogger("dograh_password_reset.test"))
    assert ok is False
    assert "@" not in caplog.text
    assert "TOKEN-SECRET-VALUE" not in caplog.text
    assert "user@example.test" not in caplog.text
    error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(error_records) == 1
    assert "reset" in caplog.text


def test_send_quietly_success_returns_true(make_settings):
    settings = make_settings("webhook")
    sent = []

    class _Ok:
        def send(self, email):
            sent.append(email)

    assert mailer.send_quietly(_Ok(), _email(settings), logging.getLogger("x")) is True
    assert len(sent) == 1


def test_build_mailer_picks_transport(make_settings):
    assert isinstance(mailer.build_mailer(make_settings("smtp")), SmtpMailer)
    assert isinstance(mailer.build_mailer(make_settings("webhook")), WebhookMailer)


@pytest.mark.parametrize(
    "bad_to",
    ["a@b.test\r\nBcc: x@y.test", "a@b.test\nBcc: x@y.test"],
)
def test_send_quietly_survives_header_injection_in_to(make_settings, caplog, bad_to):
    settings = make_settings("smtp", smtp_host="127.0.0.1", smtp_port=_free_port(), smtp_starttls=False)
    email = messages.reset_email(settings, bad_to, LINK)
    with caplog.at_level(logging.DEBUG):
        ok = mailer.send_quietly(SmtpMailer(settings), email, logging.getLogger("dograh_password_reset.test"))
    assert ok is False
    assert "@" not in caplog.text
    assert "x@y.test" not in caplog.text and "a@b.test" not in caplog.text
    assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 1


def test_send_quietly_survives_newline_in_product_name(make_settings, caplog):
    settings = make_settings(
        "smtp", smtp_host="127.0.0.1", smtp_port=_free_port(), smtp_starttls=False,
        product_name="Dograh\r\nBcc: x@y.test",
    )
    email = messages.reset_email(settings, TO, LINK)
    ok = mailer.send_quietly(SmtpMailer(settings), email, logging.getLogger("dograh_password_reset.test"))
    assert ok is False
    assert "x@y.test" not in caplog.text


def test_smtp_invalid_message_is_mail_error(make_settings):
    settings = make_settings("smtp", smtp_host="127.0.0.1", smtp_port=_free_port(), smtp_starttls=False)
    email = messages.reset_email(settings, "a@b.test\r\nBcc: x@y.test", LINK)
    with pytest.raises(MailError):
        SmtpMailer(settings).send(email)


def test_webhook_invalid_url_is_mail_error(make_settings):
    settings = make_settings("webhook")

    def bad_url(*args, **kwargs):
        raise httpx.InvalidURL("bad webhook url")

    with pytest.raises(MailError):
        WebhookMailer(settings, http_post=bad_url).send(_email(settings))


def test_send_quietly_oserror_branch(make_settings, caplog):
    settings = make_settings("webhook")

    class _OSErr:
        def send(self, email):
            raise OSError(f"connection refused by relay for {email.to}")

    with caplog.at_level(logging.DEBUG):
        ok = mailer.send_quietly(_OSErr(), _email(settings), logging.getLogger("dograh_password_reset.test"))
    assert ok is False
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert "@" not in caplog.text
    assert "user@example.test" not in caplog.text
