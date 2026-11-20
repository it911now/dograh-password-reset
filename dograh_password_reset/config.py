"""Settings for the password-reset add-on, read from environment variables.

Secrets are never taken from the environment directly: each one is read from a
file named by a *_FILE variable. Secret fields are hidden from repr().
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

LOCALHOST_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})
TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class ConfigError(Exception):
    """A setting is missing or invalid. The message names the setting."""


@dataclass(frozen=True)
class Settings:
    database_url: str = field(repr=False)
    dograh_api_url: str
    public_base_url: str
    base_path: str
    dograh_login_path: str
    ttl_minutes: int
    mail_transport: str
    smtp_host: str | None
    smtp_port: int
    smtp_starttls: bool
    smtp_username: str | None
    smtp_password: str | None = field(repr=False)
    mail_from: str | None
    mail_webhook_url: str | None
    webhook_secret: str | None = field(repr=False)
    product_name: str
    support_text: str
    trust_cloudflare: bool
    trusted_proxies: tuple[str, ...]
    db_pool_size: int = 4


def _get(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _required(env: Mapping[str, str], name: str) -> str:
    value = _get(env, name)
    if value is None:
        raise ConfigError(f"{name} is required")
    return value


def _read_secret_file(env: Mapping[str, str], name: str, required: bool) -> str | None:
    path = _get(env, name)
    if path is None:
        if required:
            raise ConfigError(f"{name} is required")
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            content = handle.read().strip()
    except OSError as exc:
        raise ConfigError(f"{name}: cannot read {path}: {exc.strerror}") from None
    if not content:
        raise ConfigError(f"{name}: file {path} is empty")
    return content


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    value = _get(env, name)
    if value is None:
        return default
    lowered = value.lower()
    if lowered in TRUE_VALUES:
        return True
    if lowered in FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be true or false")


def _int(env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    value = _get(env, name)
    if value is None:
        return default
    try:
        number = int(value)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number") from None
    if not minimum <= number <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return number


def _path(env: Mapping[str, str], name: str, default: str) -> str:
    raw = _get(env, name) or default
    if not raw.startswith("/"):
        raise ConfigError(f"{name} must start with '/'")
    return raw.rstrip("/") or "/"  # "/" stays "/" when it is the whole path


def _http_url(env: Mapping[str, str], name: str) -> str:
    value = _required(env, name).rstrip("/")
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ConfigError(f"{name} must be an http or https URL")  # the value may hold credentials: not echoed
    return value


def _public_base_url(env: Mapping[str, str]) -> str:
    value = _required(env, "PUBLIC_BASE_URL").rstrip("/")
    parts = urlsplit(value)
    if parts.scheme == "https" and parts.netloc:
        return value
    if parts.scheme == "http" and parts.hostname in LOCALHOST_NAMES:
        return value
    raise ConfigError("PUBLIC_BASE_URL must be an https URL (http is allowed only for localhost)")


def _trusted_proxies(env: Mapping[str, str]) -> tuple[str, ...]:
    raw = env.get("TRUSTED_PROXIES", "")
    entries = tuple(item.strip() for item in raw.split(",") if item.strip())
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise ConfigError("TRUSTED_PROXIES has an invalid CIDR entry") from None
    return entries


def load_settings(env: Mapping[str, str]) -> Settings:
    """Build Settings from an environment mapping. Raises ConfigError naming the bad setting."""
    database_url = _read_secret_file(env, "DATABASE_URL_FILE", required=True)
    dograh_api_url = _http_url(env, "DOGRAH_API_URL")
    public_base_url = _public_base_url(env)
    base_path = _path(env, "BASE_PATH", "/password-reset")
    dograh_login_path = _path(env, "DOGRAH_LOGIN_PATH", "/auth/login")
    ttl_minutes = _int(env, "RESET_TOKEN_TTL_MINUTES", 30, minimum=1, maximum=1440)

    transport = _required(env, "MAIL_TRANSPORT").lower()
    if transport not in ("smtp", "webhook"):
        raise ConfigError("MAIL_TRANSPORT must be 'smtp' or 'webhook'")

    smtp_host = mail_from = smtp_username = smtp_password = None
    mail_webhook_url = webhook_secret = None
    if transport == "smtp":
        smtp_host = _required(env, "SMTP_HOST")
        mail_from = _required(env, "MAIL_FROM")
        smtp_username = _get(env, "SMTP_USERNAME")
        smtp_password = _read_secret_file(env, "SMTP_PASSWORD_FILE", required=False)
    else:
        mail_webhook_url = _http_url(env, "MAIL_WEBHOOK_URL")
        webhook_secret = _read_secret_file(env, "MAIL_WEBHOOK_SECRET_FILE", required=True)

    return Settings(
        database_url=database_url,
        dograh_api_url=dograh_api_url,
        public_base_url=public_base_url,
        base_path=base_path,
        dograh_login_path=dograh_login_path,
        ttl_minutes=ttl_minutes,
        mail_transport=transport,
        smtp_host=smtp_host,
        smtp_port=_int(env, "SMTP_PORT", 587, minimum=1, maximum=65535),
        smtp_starttls=_bool(env, "SMTP_STARTTLS", True),
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        mail_from=mail_from,
        mail_webhook_url=mail_webhook_url,
        webhook_secret=webhook_secret,
        product_name=_get(env, "PRODUCT_NAME") or "Dograh",
        support_text=env.get("SUPPORT_TEXT", "").strip(),
        trust_cloudflare=_bool(env, "TRUST_CLOUDFLARE", False),
        trusted_proxies=_trusted_proxies(env),
        db_pool_size=_int(env, "DB_POOL_SIZE", 4, minimum=1, maximum=50),
    )
