import bcrypt

from dograh_password_reset import passwords

EMAIL = "user@example.test"
GOOD = "correct horse battery"


def test_valid_password_has_no_messages():
    assert passwords.validate(GOOD, GOOD, EMAIL) == []


def test_too_short():
    assert passwords.validate("short", "short", EMAIL) == ["Use at least 12 characters."]


def test_over_72_bytes_with_multibyte():
    pw = "€" * 25  # 25 characters, 75 bytes
    assert passwords.validate(pw, pw, EMAIL) == [
        "Use at most 72 bytes (fewer if you use accents or symbols)."
    ]


def test_exactly_72_bytes_ok():
    pw = "a" * 72
    assert passwords.validate(pw, pw, EMAIL) == []


def test_not_the_email_case_insensitive():
    assert passwords.validate("USER@example.test", "USER@example.test", EMAIL) == [
        "Don't use your email address as your password."
    ]


def test_mismatch():
    assert passwords.validate(GOOD, GOOD + "x", EMAIL) == ["The two passwords don't match."]


def test_hash_is_bcrypt_and_verifies():
    hashed = passwords.hash(GOOD)
    assert hashed.startswith("$2b$12$")
    assert bcrypt.checkpw(GOOD.encode(), hashed.encode())
