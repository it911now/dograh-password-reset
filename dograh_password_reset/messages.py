"""Email content. Each message has a plain-text and an HTML part, rendered from templates/.

The HTML templates autoescape variables (product name, link, support text). The text
templates do not escape, because they are plain text.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from .config import Settings

TEMPLATE_DIR = Path(__file__).with_name("templates")

_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(enabled_extensions=("html",)),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
)


@dataclass(frozen=True)
class Email:
    to: str
    subject: str
    text: str
    html: str
    kind: Literal["reset", "changed"]


def _render(name: str, **context: object) -> str:
    return _env.get_template(name).render(**context)


def reset_email(settings: Settings, to: str, link: str) -> Email:
    context = {
        "product_name": settings.product_name,
        "link": link,
        "ttl_minutes": settings.ttl_minutes,
        "support_text": settings.support_text,
    }
    return Email(
        to=to,
        subject=f"Reset your {settings.product_name} password",
        text=_render("email_reset.txt", **context),
        html=_render("email_reset.html", **context),
        kind="reset",
    )


def changed_email(settings: Settings, to: str) -> Email:
    context = {"product_name": settings.product_name, "support_text": settings.support_text}
    return Email(
        to=to,
        subject=f"Your {settings.product_name} password was changed",
        text=_render("email_changed.txt", **context),
        html=_render("email_changed.html", **context),
        kind="changed",
    )
