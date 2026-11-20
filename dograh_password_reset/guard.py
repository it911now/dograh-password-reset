"""Startup checks: refuse to run unless Dograh answers, uses local login, and its users
table has the columns this add-on needs. The add-on's own schema is created here too."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

import httpx
import psycopg

from . import db
from .config import Settings

log = logging.getLogger(__name__)

TRIES = 5
DELAY_SECONDS = 3.0
TIMEOUT_SECONDS = 5.0

# (url, timeout) -> (HTTP status, parsed JSON body)
HealthGet = Callable[[str, float], tuple[int, dict]]


class GuardError(Exception):
    """Dograh is not usable with this add-on. The message is safe to log."""


def _default_get(url: str, timeout: float) -> tuple[int, dict]:
    response = httpx.get(url, timeout=timeout)
    return response.status_code, response.json()


def check_dograh(
    api_url: str,
    http_get: HealthGet = _default_get,
    *,
    sleep: Callable[[float], None] = time.sleep,
    tries: int = TRIES,
    delay: float = DELAY_SECONDS,
) -> str:
    """Return Dograh's version. Retries an unreachable API; fails at once on a non-local login."""
    url = api_url.rstrip("/") + "/api/v1/health"
    last_problem = "no response"
    for attempt in range(tries):
        if attempt:
            sleep(delay)
        try:
            status, body = http_get(url, TIMEOUT_SECONDS)
        except (OSError, httpx.HTTPError, ValueError) as exc:
            last_problem = type(exc).__name__
            continue
        if status != 200 or not isinstance(body, dict):
            last_problem = f"HTTP {status}"
            continue
        if body.get("auth_provider") != "local":
            raise GuardError("Dograh auth_provider is not 'local'; this add-on only supports local login.")
        return str(body.get("version", "unknown"))
    raise GuardError(f"Dograh health check failed after {tries} tries ({last_problem}).")


def startup(settings: Settings, conn: psycopg.Connection) -> None:
    version = check_dograh(settings.dograh_api_url)
    db.check_users_table(conn)
    db.ensure_schema(conn)
    log.info("dograh-password-reset ready (dograh %s)", version)
