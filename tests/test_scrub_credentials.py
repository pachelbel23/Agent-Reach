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


def test_scrubs_additional_sensitive_query_parameters():
    raw = (
        "https://example.test/oauth/token?"
        "refresh_token=rt_secret&id_token=id_secret&"
        "client_secret=cs_secret&app_secret=as_secret&"
        "private_key=pk_secret&authorization=bearer_val&"
        "x-api-key=x_key_val&session_token=st_secret"
    )
    scrubbed = scrub_url_credentials(raw)

    assert "rt_secret" not in scrubbed
    assert "id_secret" not in scrubbed
    assert "cs_secret" not in scrubbed
    assert "as_secret" not in scrubbed
    assert "pk_secret" not in scrubbed
    assert "bearer_val" not in scrubbed
    assert "x_key_val" not in scrubbed
    assert "st_secret" not in scrubbed
    assert scrubbed == (
        "https://example.test/oauth/token?"
        "refresh_token=***&id_token=***&"
        "client_secret=***&app_secret=***&"
        "private_key=***&authorization=***&"
        "x-api-key=***&session_token=***"
    )


def test_leaves_non_secret_urls_and_plain_text_unchanged():
    raw = "See https://example.test/search?q=python&page=2 after timeout"
    assert scrub_url_credentials(raw) == raw




