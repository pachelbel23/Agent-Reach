"""Secrets embedded in URLs must not reach user-facing diagnostics."""



from agent_reach.utils.text import scrub_url_credentials


def test_scrubs_userinfo_and_sensitive_query_values():
    raw = (
        "proxy http://user:pass@proxy.example:8080 failed; "
        "upstream https://api.example.test/path?access_token=secret"
        "&page=2&api_key=another-secret"
    )

    scrubbed = scrub_url_credentials(raw)

    assert "user:pass" not in scrubbed
    assert "secret" not in scrubbed
    assert "another-secret" not in scrubbed
    assert "http://***@proxy.example:8080" in scrubbed
    assert "access_token=***" in scrubbed
    assert "page=2" in scrubbed
    assert "api_key=***" in scrubbed


def test_scrubs_multiple_schemes_and_fragment_tokens():
    raw = (
        "socks5://token@host:1080 "
        "https://example.test/#auth_token=fragment-secret"
    )

    scrubbed = scrub_url_credentials(ValueError(raw))

    assert scrubbed == (
        "socks5://***@host:1080 "
        "https://example.test/#auth_token=***"
    )


def test_scrubs_bare_user_password_host_diagnostics():
    raw = "proxy handshake for user:pass@proxy.test failed"
    assert scrub_url_credentials(raw) == "proxy handshake for ***@proxy.test failed"


def test_leaves_non_secret_urls_and_plain_text_unchanged():
    raw = "See https://example.test/search?q=python&page=2 after timeout"
    assert scrub_url_credentials(raw) == raw


def test_scrubs_extended_sensitive_query_parameters():
    raw = (
        "https://example.test/api?"
        "client_secret=secret1&authorization=Bearer123&refresh_token=rt456&"
        "id_token=it789&app_secret=as101&private_key=pk202&session_token=st303&"
        "x-api-key=xak404&keyword=python&page=1"
    )

    scrubbed = scrub_url_credentials(raw)

    assert "secret1" not in scrubbed
    assert "Bearer123" not in scrubbed
    assert "rt456" not in scrubbed
    assert "it789" not in scrubbed
    assert "as101" not in scrubbed
    assert "pk202" not in scrubbed
    assert "st303" not in scrubbed
    assert "xak404" not in scrubbed
    assert "client_secret=***" in scrubbed
    assert "authorization=***" in scrubbed
    assert "refresh_token=***" in scrubbed
    assert "id_token=***" in scrubbed
    assert "app_secret=***" in scrubbed
    assert "private_key=***" in scrubbed
    assert "session_token=***" in scrubbed
    assert "x-api-key=***" in scrubbed
    assert "keyword=python" in scrubbed
    assert "page=1" in scrubbed


