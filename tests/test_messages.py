from dograh_password_reset import messages

LINK = "https://dograh.example.test/password-reset/new?token=abc-DEF_123"


def test_reset_email_contains_link_and_ttl(make_settings):
    settings = make_settings()
    email = messages.reset_email(settings, "user@example.test", LINK)
    assert email.kind == "reset"
    assert email.to == "user@example.test"
    assert email.subject == "Reset your Dograh password"
    for body in (email.text, email.html):
        assert LINK in body
        assert "30 minutes" in body
        assert "If you didn't ask for this, ignore this email; your password stays the same." in body


def test_changed_email(make_settings):
    settings = make_settings()
    email = messages.changed_email(settings, "user@example.test")
    assert email.kind == "changed"
    assert email.subject == "Your Dograh password was changed"
    assert "token=" not in email.text and "token=" not in email.html


def test_html_escapes_product_name(make_settings):
    settings = make_settings(product_name="<script>alert(1)</script> & Co")
    email = messages.reset_email(settings, "user@example.test", LINK)
    assert "<script>" not in email.html
    assert "&lt;script&gt;" in email.html
    assert "&amp; Co" in email.html
    assert email.subject == "Reset your <script>alert(1)</script> & Co password"
    # The text part is plain text, so it keeps the raw name.
    assert "<script>alert(1)</script> & Co" in email.text


def test_support_text_is_optional(make_settings):
    without = messages.reset_email(make_settings(support_text=""), "user@example.test", LINK)
    assert "Need help" not in without.text
    with_text = messages.reset_email(
        make_settings(support_text="Need help? Email support@example.test"),
        "user@example.test",
        LINK,
    )
    assert "Need help? Email support@example.test" in with_text.text
    assert "Need help? Email support@example.test" in with_text.html
