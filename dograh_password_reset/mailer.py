"""Mail transports: SMTP (stdlib smtplib) and a signed JSON webhook (httpx).

Failures raise MailError. The message never contains an address, token or secret.
send_quietly() is the only entry point the web layer uses: it logs one line and never raises.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
import ssl
from collections.abc import Callable, Mapping
from email.message import EmailMessage
from logging import Logger
from typing import Protocol

import httpx

from .config import Settings
from .messages import Email
from .tokens import sha256_hex

TIMEOUT_SECONDS = 10
SIGNATURE_HEADER = "X-Dograh-Reset-Signature"

# (url, body, headers, timeout) -> HTTP status code
HttpPost = Callable[[str, bytes, Mapping[str, str], float], int]


class MailError(Exception):
    """The email could not be handed to the transport."""


class Mailer(Protocol):
    def send(self, email: Email) -> None: ...


def sign(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return "sha256=" + digest


def _to_message(settings: Settings, email: Email) -> EmailMessage:
    message = EmailMessage()
    message["From"] = settings.mail_from
    message["To"] = email.to
    message["Subject"] = email.subject
    message.set_content(email.text)
    message.add_alternative(email.html, subtype="html")
    return message


class SmtpMailer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def send(self, email: Email) -> None:
        s = self._settings
        try:
            message = _to_message(s, email)
        except (ValueError, TypeError):
            # CR/LF in an address or subject makes EmailMessage raise; keep the error opaque.
            raise MailError("smtp message invalid") from None
        try:
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=TIMEOUT_SECONDS) as smtp:
                if s.smtp_starttls:
                    smtp.starttls(context=ssl.create_default_context())
                if s.smtp_username:
                    smtp.login(s.smtp_username, s.smtp_password or "")
                smtp.send_message(message)
        except (smtplib.SMTPException, OSError) as exc:
            # Only the exception type: SMTP error text can echo recipient addresses.
            raise MailError(f"smtp send failed ({type(exc).__name__})") from None


def _httpx_post(url: str, body: bytes, headers: Mapping[str, str], timeout: float) -> int:
    return httpx.post(url, content=body, headers=dict(headers), timeout=timeout).status_code


class WebhookMailer:
    def __init__(self, settings: Settings, http_post: HttpPost | None = None) -> None:
        self._url = settings.mail_webhook_url
        self._secret = settings.webhook_secret or ""
        self._post = http_post or _httpx_post

    def send(self, email: Email) -> None:
        # Serialise once: the signature covers exactly these bytes, and these bytes are sent.
        payload = {
            "to": email.to,
            "subject": email.subject,
            "text": email.text,
            "html": email.html,
            "kind": email.kind,
        }
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            SIGNATURE_HEADER: sign(body, self._secret),
        }
        try:
            status = self._post(self._url, body, headers, float(TIMEOUT_SECONDS))
        except (OSError, httpx.HTTPError, httpx.InvalidURL) as exc:
            raise MailError(f"webhook request failed ({type(exc).__name__})") from None
        if not 200 <= status < 300:
            raise MailError(f"webhook returned HTTP {status}")


def build_mailer(settings: Settings) -> Mailer:
    if settings.mail_transport == "smtp":
        return SmtpMailer(settings)
    return WebhookMailer(settings)


def send_quietly(m: Mailer, email: Email, log: Logger) -> bool:
    """Send and return True, or log one line (kind and a hash of the address) and return False."""
    try:
        m.send(email)
    except (MailError, OSError) as exc:
        # Exception class only: error text can echo addresses or hosts.
        log.error(
            "password reset email not sent: kind=%s to=%s error=%s",
            email.kind,
            sha256_hex(email.to)[:12],
            type(exc).__name__,
        )
        return False
    return True
