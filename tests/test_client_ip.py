from dograh_password_reset.client_ip import resolve


def test_cf_header_ignored_when_not_trusted(make_settings):
    s = make_settings(trust_cloudflare=False)
    assert resolve("203.0.113.9", {"CF-Connecting-IP": "198.51.100.7"}, s) == "203.0.113.9"


def test_cf_header_honoured_when_trusted(make_settings):
    s = make_settings(trust_cloudflare=True)
    assert resolve("203.0.113.9", {"cf-connecting-ip": "198.51.100.7"}, s) == "198.51.100.7"


def test_cf_header_garbage_falls_back_to_peer(make_settings):
    s = make_settings(trust_cloudflare=True)
    assert resolve("203.0.113.9", {"CF-Connecting-IP": "not-an-ip"}, s) == "203.0.113.9"


def test_xff_ignored_from_untrusted_peer(make_settings):
    s = make_settings(trusted_proxies=("10.0.0.0/8",))
    assert resolve("203.0.113.9", {"X-Forwarded-For": "198.51.100.7"}, s) == "203.0.113.9"


def test_xff_ignored_when_no_trusted_proxies(make_settings):
    s = make_settings()
    assert resolve("10.0.0.2", {"X-Forwarded-For": "198.51.100.7"}, s) == "10.0.0.2"


def test_xff_rightmost_untrusted_hop_from_trusted_peer(make_settings):
    s = make_settings(trusted_proxies=("10.0.0.0/8",))
    headers = {"X-Forwarded-For": "1.2.3.4, 198.51.100.7, 10.0.0.5"}
    assert resolve("10.0.0.2", headers, s) == "198.51.100.7"


def test_xff_all_trusted_returns_peer(make_settings):
    s = make_settings(trusted_proxies=("10.0.0.0/8",))
    assert resolve("10.0.0.2", {"X-Forwarded-For": "10.0.0.5"}, s) == "10.0.0.2"
