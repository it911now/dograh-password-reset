import io
import os
import re
import sys
from urllib.parse import parse_qs, urlsplit

import bcrypt
import pytest
from fastapi.testclient import TestClient

from dograh_password_reset import cli, tokens
from dograh_password_reset.config import load_settings
from dograh_password_reset.db import connect
from dograh_password_reset.web import create_app
from datetime import datetime, timezone

EMAIL = "user@example.test"
OLD_PW = "old password 123"
NEW_PW = "brand new password 456"


@pytest.fixture
def cli_env(ready_db, tmp_path, monkeypatch):
    """Environment the CLI reads: a real DATABASE_URL_FILE pointing at the test database."""
    db_file = tmp_path / "database_url"
    db_file.write_text(os.environ["TEST_DATABASE_URL"] + "\n", encoding="utf-8")
    secret_file = tmp_path / "webhook_secret"
    secret_file.write_text("cli-test-secret\n", encoding="utf-8")
    env = {
        "DATABASE_URL_FILE": str(db_file),
        "DOGRAH_API_URL": "http://api:8000",
        "PUBLIC_BASE_URL": "https://dograh.example.test",
        "MAIL_TRANSPORT": "webhook",
        "MAIL_WEBHOOK_URL": "https://hooks.example.test/reset",
        "MAIL_WEBHOOK_SECRET_FILE": str(secret_file),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return env


def stored_hash(db, email=EMAIL):
    db.commit()
    return db.execute("SELECT password_hash FROM users WHERE email = %s", (email,)).fetchone()[0]


def feed_stdin(monkeypatch, text):
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


def test_cli_set_password_from_stdin(cli_env, user, ready_db, monkeypatch, capsys):
    user(EMAIL, OLD_PW)
    feed_stdin(monkeypatch, NEW_PW + "\n")
    assert cli.main(["set-password", EMAIL]) == 0
    captured = capsys.readouterr()
    assert "Password updated." in captured.out
    assert NEW_PW not in captured.out + captured.err
    assert bcrypt.checkpw(NEW_PW.encode(), stored_hash(ready_db).encode())


def test_cli_set_password_invalidates_outstanding_tokens(cli_env, user, ready_db, monkeypatch, capsys):
    user_id = user(EMAIL, OLD_PW)
    assert cli.main(["generate-link", EMAIL]) == 0
    link = re.search(r"https://\S+", capsys.readouterr().out).group(0)
    token = parse_qs(urlsplit(link).query)["token"][0]
    assert tokens.peek(ready_db, token, datetime.now(timezone.utc)) == user_id
    feed_stdin(monkeypatch, NEW_PW + "\n")
    assert cli.main(["set-password", EMAIL]) == 0
    assert tokens.peek(ready_db, token, datetime.now(timezone.utc)) is None


def test_cli_rejects_short_password(cli_env, user, ready_db, monkeypatch, capsys):
    user(EMAIL, OLD_PW)
    before = stored_hash(ready_db)
    feed_stdin(monkeypatch, "short\n")
    assert cli.main(["set-password", EMAIL]) == 1
    assert "Use at least 12 characters." in capsys.readouterr().out
    assert stored_hash(ready_db) == before


def test_cli_unknown_email(cli_env, monkeypatch, capsys):
    feed_stdin(monkeypatch, NEW_PW + "\n")
    assert cli.main(["set-password", "nobody@example.test"]) == 1
    assert cli.main(["generate-link", "nobody@example.test"]) == 1
    assert capsys.readouterr().out.count("No account with that email.") == 2


def test_cli_generate_link_works_in_web(cli_env, user, ready_db, capsys):
    user(EMAIL, OLD_PW)
    assert cli.main(["generate-link", EMAIL]) == 0
    link = re.search(r"https://\S+", capsys.readouterr().out).group(0)
    assert link.startswith("https://dograh.example.test/password-reset/new?token=")
    dsn = os.environ["TEST_DATABASE_URL"]
    settings = load_settings(os.environ)
    app = create_app(settings, lambda: connect(dsn), None, lambda: datetime.now(timezone.utc))
    client = TestClient(app, base_url=settings.public_base_url)
    resp = client.get(urlsplit(link).path, params={"token": parse_qs(urlsplit(link).query)["token"][0]})
    assert resp.status_code == 200
    assert 'name="password"' in resp.text
