"""Password rules and hashing. Matches Dograh: bcrypt with the default cost."""

from __future__ import annotations

import bcrypt

MIN_CHARS = 12
MAX_BYTES = 72  # bcrypt ignores (or, in newer versions, rejects) anything longer

MSG_SHORT = "Use at least 12 characters."
MSG_LONG = "Use at most 72 bytes (fewer if you use accents or symbols)."
MSG_EMAIL = "Don't use your email address as your password."
MSG_MISMATCH = "The two passwords don't match."


def validate(pw: str, confirm: str, email: str) -> list[str]:
    """Return the messages for every rule the password breaks (empty list = acceptable)."""
    problems: list[str] = []
    if len(pw) < MIN_CHARS:
        problems.append(MSG_SHORT)
    try:
        too_long = len(pw.encode("utf-8")) > MAX_BYTES
    except UnicodeEncodeError:
        too_long = True  # lone surrogates cannot be stored; report as unusable
    if too_long:
        problems.append(MSG_LONG)
    if pw.strip().lower() == email.strip().lower():
        problems.append(MSG_EMAIL)
    if pw != confirm:
        problems.append(MSG_MISMATCH)
    return problems


def hash(pw: str) -> str:  # noqa: A001 - public name fixed by the interface
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("ascii")
