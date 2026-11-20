"""HTTP routes: request form, emailed link, set-new-password form, health and the login-page snippet."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from fastapi import APIRouter, BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from . import guard, passwords, tokens
from .client_ip import resolve
from .config import Settings, load_settings
from .db import SchemaError, connect, find_user, user_email
from .mailer import Mailer, build_mailer, send_quietly
from .messages import changed_email, reset_email
from .ratelimit import allow
from .tokens import sha256_hex

log = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).parent
CSRF_COOKIE = "dpr_csrf"
MAX_EMAIL_LENGTH = 320
MAX_TOKEN_LENGTH = 200
PURGE_INTERVAL_SECONDS = 3600
DB_WAIT_SECONDS = 3.0  # how long a request waits for a free database slot before it is turned away


class DbBusy(Exception):
    """All database slots are in use (see DB_POOL_SIZE)."""

_env = Environment(
    loader=FileSystemLoader(PACKAGE_DIR / "templates"),
    autoescape=select_autoescape(enabled_extensions=("html",)),
    undefined=StrictUndefined,
)

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
}


class RedactTokenFilter(logging.Filter):
    """Keeps reset tokens out of access logs (the emailed link carries one in the URL)."""

    pattern = re.compile(r"(token=)[^&\s\"']+")

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                self.pattern.sub(r"\1REDACTED", a) if isinstance(a, str) else a for a in record.args
            )
        if isinstance(record.msg, str):
            record.msg = self.pattern.sub(r"\1REDACTED", record.msg)
        return True


class ScrubExceptionFilter(logging.Filter):
    """Keeps exception text out of the logs: a record that carries an exception is logged with the
    exception class name only. uvicorn re-raises after our 500 handler and logs the full traceback,
    whose message (a database error, a URL) can hold an email address or a token. The add-on's own
    start-up errors (GuardError, SchemaError) have messages written to be safe, and the operator needs
    them, so those pass through."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.exc_info and record.exc_info[0] is not None:
            if issubclass(record.exc_info[0], (guard.GuardError, SchemaError)):
                return True
            name = record.exc_info[0].__name__
            record.msg = f"{record.getMessage()} [{name}]"
            record.args = None
            record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def _unusable_email(email: str) -> bool:
    if not email or len(email) > MAX_EMAIL_LENGTH:
        return True
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in email):
        return True
    try:
        email.encode("utf-8")  # lone surrogates fail here
    except UnicodeEncodeError:
        return True
    return False


def create_app(
    settings: Settings,
    conn_factory: Callable[[], psycopg.Connection],
    mailer: Mailer,
    clock: Callable[[], datetime],
    lifespan: Callable | None = None,
) -> FastAPI:
    base = settings.base_path.rstrip("/")  # "/" (root) becomes "" so routes do not get a double slash
    login_url = settings.public_base_url + settings.dograh_login_path
    secure_cookie = settings.public_base_url.startswith("https://")
    inject_js = (
        (PACKAGE_DIR / "static" / "inject.js")
        .read_text(encoding="utf-8")
        .replace("__LOGIN_PATH__", json.dumps(settings.dograh_login_path))
        .replace("__LINK__", json.dumps(base + "/"))
    )

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    router = APIRouter(prefix=base)

    @app.middleware("http")
    async def add_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.exception_handler(Exception)
    async def unhandled(_request: Request, exc: Exception):
        # Error responses bypass the middleware above, so the headers are set here.
        # Only the class is logged: the message or the URL can carry a token.
        log.error("unhandled error: %s", type(exc).__name__)
        return PlainTextResponse(
            "Something went wrong. Please try again later.", status_code=500, headers=SECURITY_HEADERS
        )

    def render(request: Request, name: str, status: int = 200, csrf: str | None = None, **ctx) -> HTMLResponse:
        csrf_value = csrf or request.cookies.get(CSRF_COOKIE) or ""
        if not re.fullmatch(r"[\w-]{20,100}", csrf_value):
            csrf_value = secrets.token_urlsafe(24)
        html = _env.get_template(name).render(
            product_name=settings.product_name,
            support_text=settings.support_text,
            ttl_minutes=settings.ttl_minutes,
            base_path=base,
            login_url=login_url,
            csrf=csrf_value,
            **ctx,
        )
        response = HTMLResponse(html, status_code=status)
        response.set_cookie(
            CSRF_COOKIE, csrf_value, path=base or "/", httponly=True,
            secure=secure_cookie, samesite="lax", max_age=3600,
        )
        return response

    def csrf_ok(request: Request, form_value: str) -> bool:
        cookie = request.cookies.get(CSRF_COOKIE, "")
        return bool(cookie) and hmac.compare_digest(cookie.encode(), form_value.encode("utf-8", "replace"))

    # At most settings.db_pool_size request connections are open at once. A request that cannot get
    # a slot within DB_WAIT_SECONDS fails soft instead of opening yet another connection. (A
    # semaphore rather than psycopg_pool: each request opens its own short-lived connection and
    # closes it, which keeps every transaction isolated and needs no pool lifecycle or extra dependency.)
    db_slots = threading.BoundedSemaphore(settings.db_pool_size)

    @contextlib.contextmanager
    def db_conn() -> Iterator[psycopg.Connection]:
        if not db_slots.acquire(timeout=DB_WAIT_SECONDS):
            raise DbBusy
        try:
            conn = conn_factory()
            try:
                yield conn
            finally:
                conn.close()
        finally:
            db_slots.release()

    @app.exception_handler(DbBusy)
    async def busy(_request: Request, _exc: DbBusy):
        log.warning("database slots exhausted; request turned away")
        return PlainTextResponse(
            "The service is busy. Please try again in a moment.",
            status_code=503,
            headers={**SECURITY_HEADERS, "Retry-After": "5"},
        )

    def request_job(email: str, ip: str) -> None:
        # Runs after the response. Nothing here may reach the user or log an address/token.
        try:
            with db_conn() as conn:
                now = clock()
                if not allow(conn, email, ip, now):
                    return
                found = find_user(conn, email)
                if found is None:
                    return
                raw = tokens.issue(conn, found.id, settings.ttl_minutes, sha256_hex(ip), now)
                link = f"{settings.public_base_url}{base}/new?token={raw}"
                send_quietly(mailer, reset_email(settings, found.email, link), log)
        except DbBusy:
            log.warning("password reset request dropped: database slots exhausted")
        except Exception as exc:  # noqa: BLE001 - the neutral page must never depend on this
            log.error("password reset request job failed: %s", type(exc).__name__)

    def changed_job(email: str) -> None:
        try:
            send_quietly(mailer, changed_email(settings, email), log)
        except Exception as exc:  # noqa: BLE001
            log.error("password changed notice failed: %s", type(exc).__name__)

    @router.get("/", response_class=HTMLResponse)
    def request_form(request: Request):
        return render(request, "request.html")

    @router.post("/request", response_class=HTMLResponse)
    def request_reset(
        request: Request,
        background: BackgroundTasks,
        email: str = Form(""),
        csrf: str = Form(""),
    ):
        if not csrf_ok(request, csrf):
            return PlainTextResponse("Invalid form submission. Reload the page and try again.", status_code=403)
        email = email.strip()
        if not _unusable_email(email):
            client = request.client.host if request.client else "unknown"
            ip = resolve(client, request.headers, settings)
            background.add_task(request_job, email, ip)
        return render(request, "sent.html")

    @router.get("/new", response_class=HTMLResponse)
    def new_form(request: Request, token: str = ""):
        valid = False
        if token and len(token) <= MAX_TOKEN_LENGTH:
            with db_conn() as conn:
                valid = tokens.peek(conn, token, clock()) is not None
        if not valid:
            return render(request, "invalid.html", status=400)
        return render(request, "new.html", token=token, errors=[])

    @router.post("/new", response_class=HTMLResponse)
    def new_submit(
        request: Request,
        background: BackgroundTasks,
        token: str = Form(""),
        password: str = Form(""),
        confirm: str = Form(""),
        csrf: str = Form(""),
    ):
        if not csrf_ok(request, csrf):
            return PlainTextResponse("Invalid form submission. Reload the page and try again.", status_code=403)
        if not token or len(token) > MAX_TOKEN_LENGTH:
            return render(request, "invalid.html", status=400)
        with db_conn() as conn:
            user_id = tokens.peek(conn, token, clock())
            email = user_email(conn, user_id) if user_id is not None else None
            if user_id is None or email is None:
                return render(request, "invalid.html", status=400)
            errors = passwords.validate(password, confirm, email)
            new_hash = None
            if not errors:
                try:
                    new_hash = passwords.hash(password)
                except ValueError:
                    errors = ["That password can't be used. Choose a different one."]
            if errors:
                return render(request, "new.html", status=400, token=token, errors=errors)
            if not tokens.consume(conn, token, new_hash, clock()):
                return render(request, "invalid.html", status=400)
        background.add_task(changed_job, email)
        return render(request, "done.html")

    @router.get("/inject.js")
    def inject():
        return Response(inject_js, media_type="application/javascript")

    @router.get("/healthz")
    def healthz():
        try:
            with db_conn() as conn:
                conn.execute("SELECT 1")
                conn.rollback()
        except Exception:  # noqa: BLE001
            return PlainTextResponse("database unreachable", status_code=503)
        return PlainTextResponse("ok")

    app.include_router(router)
    return app


def _startup_checks(settings: Settings, conn_factory: Callable[[], psycopg.Connection]) -> None:
    conn = conn_factory()
    try:
        guard.startup(settings, conn)
    finally:
        conn.close()


def _purge_once(conn_factory: Callable[[], psycopg.Connection], now: datetime) -> None:
    conn = conn_factory()
    try:
        removed = tokens.purge(conn, now)
    finally:
        conn.close()
    if removed:
        log.info("purged %d expired or used reset rows", removed)


async def _purge_forever(conn_factory: Callable[[], psycopg.Connection], clock: Callable[[], datetime]) -> None:
    while True:
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)
        try:
            await asyncio.to_thread(_purge_once, conn_factory, clock())
        except Exception as exc:  # noqa: BLE001 - the loop must survive any failure
            log.error("token purge failed: %s", type(exc).__name__)


def make_lifespan(
    settings: Settings,
    conn_factory: Callable[[], psycopg.Connection],
    clock: Callable[[], datetime],
) -> Callable:
    """Startup: refuse to start unless the guard passes. Then purge hourly until shutdown."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await asyncio.to_thread(_startup_checks, settings, conn_factory)
        purge = asyncio.create_task(_purge_forever(conn_factory, clock))
        try:
            yield
        finally:
            purge.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await purge

    return lifespan


def app_from_env() -> FastAPI:
    """Build the real app from the environment (the uvicorn --factory entry point)."""
    settings = load_settings(os.environ)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # keep request URLs out of the logs
    logging.getLogger("uvicorn.access").addFilter(RedactTokenFilter())
    logging.getLogger("uvicorn.error").addFilter(ScrubExceptionFilter())

    def conn_factory() -> psycopg.Connection:
        return connect(settings.database_url)

    def clock() -> datetime:
        return datetime.now(timezone.utc)

    return create_app(
        settings,
        conn_factory,
        build_mailer(settings),
        clock,
        lifespan=make_lifespan(settings, conn_factory, clock),
    )
