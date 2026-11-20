import pytest

from dograh_password_reset.config import ConfigError, load_settings

DB_SECRET = "postgresql://dograh_password_reset:dummy-db-pass@db.example.test:5432/dograh"


@pytest.fixture
def base_env(tmp_path):
    db_file = tmp_path / "database_url"
    db_file.write_text(DB_SECRET + "\n", encoding="utf-8")
    hook_file = tmp_path / "webhook_secret"
    hook_file.write_text("dummy-webhook-secret\n", encoding="utf-8")
    return {
        "DATABASE_URL_FILE": str(db_file),
        "DOGRAH_API_URL": "http://api.example.test:8000",
        "PUBLIC_BASE_URL": "https://reset.example.test",
        "MAIL_TRANSPORT": "webhook",
        "MAIL_WEBHOOK_URL": "https://mail.example.test/hook",
        "MAIL_WEBHOOK_SECRET_FILE": str(hook_file),
    }


def test_defaults(base_env):
    s = load_settings(base_env)
    assert s.base_path == "/password-reset"
    assert s.ttl_minutes == 30
    assert s.trust_cloudflare is False
    assert s.dograh_login_path == "/auth/login"
    assert s.smtp_port == 587
    assert s.smtp_starttls is True
    assert s.product_name == "Dograh"
    assert s.support_text == ""
    assert s.trusted_proxies == ()


def test_secret_read_from_file_and_stripped(base_env):
    s = load_settings(base_env)
    assert s.database_url == DB_SECRET
    assert s.webhook_secret == "dummy-webhook-secret"


def test_secrets_hidden_from_repr(base_env):
    text = repr(load_settings(base_env))
    assert DB_SECRET not in text
    assert "dummy-webhook-secret" not in text


def test_smtp_requires_host_and_from(base_env):
    env = dict(base_env, MAIL_TRANSPORT="smtp")
    with pytest.raises(ConfigError, match="SMTP_HOST"):
        load_settings(env)
    env["SMTP_HOST"] = "smtp.example.test"
    with pytest.raises(ConfigError, match="MAIL_FROM"):
        load_settings(env)


def test_bad_transport(base_env):
    with pytest.raises(ConfigError, match="MAIL_TRANSPORT"):
        load_settings(dict(base_env, MAIL_TRANSPORT="carrier-pigeon"))


@pytest.mark.parametrize(
    "url, ok",
    [
        ("http://reset.example.test", False),
        ("http://localhost:8000", True),
        ("http://127.0.0.1:8000", True),
        ("https://reset.example.test", True),
    ],
)
def test_public_base_url_must_be_https_unless_localhost(base_env, url, ok):
    env = dict(base_env, PUBLIC_BASE_URL=url)
    if ok:
        assert load_settings(env).public_base_url == url
    else:
        with pytest.raises(ConfigError, match="PUBLIC_BASE_URL"):
            load_settings(env)


@pytest.mark.parametrize(
    "env_name, raw, expected",
    [
        ("BASE_PATH", "/password-reset/", "/password-reset"),
        ("BASE_PATH", "/password-reset///", "/password-reset"),
        ("BASE_PATH", "/", "/"),
        ("DOGRAH_LOGIN_PATH", "/auth/login/", "/auth/login"),
        ("DOGRAH_LOGIN_PATH", "/", "/"),
    ],
)
def test_paths_drop_trailing_slash_but_keep_root(base_env, env_name, raw, expected):
    settings = load_settings(dict(base_env, **{env_name: raw}))
    actual = settings.base_path if env_name == "BASE_PATH" else settings.dograh_login_path
    assert actual == expected


def test_path_without_leading_slash_is_rejected(base_env):
    with pytest.raises(ConfigError, match="BASE_PATH"):
        load_settings(dict(base_env, BASE_PATH="password-reset"))


def test_db_pool_size_default_and_bounds(base_env):
    assert load_settings(base_env).db_pool_size == 4
    assert load_settings({**base_env, "DB_POOL_SIZE": "2"}).db_pool_size == 2
    for bad in ("0", "abc", "999"):
        with pytest.raises(ConfigError, match="DB_POOL_SIZE"):
            load_settings({**base_env, "DB_POOL_SIZE": bad})


def test_config_errors_never_echo_url_values(base_env):
    for name, value in (
        ("MAIL_WEBHOOK_URL", "ftp://user:hunter2-secret@hooks.example.test/x"),
        ("DOGRAH_API_URL", "ftp://user:hunter2-secret@api.example.test"),
        ("PUBLIC_BASE_URL", "ftp://user:hunter2-secret@x.example.test"),
        ("BASE_PATH", "no-slash-hunter2-secret"),
        ("TRUSTED_PROXIES", "hunter2-secret"),
        ("SMTP_STARTTLS", "hunter2-secret"),
    ):
        with pytest.raises(ConfigError) as err:
            load_settings({**base_env, name: value})
        assert name in str(err.value)
        assert "hunter2" not in str(err.value), name
