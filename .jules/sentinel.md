## 2025-05-15 - Incomplete Sensitive Data Masking in Config
**Vulnerability:** Platform-specific session identifiers (e.g., `ct0` for Twitter, `SESSDATA` for Bilibili) and other sensitive tokens were not being masked in `Config.to_dict()`, potentially leaking credentials in logs or console output.
**Learning:** Generic keywords like "key" and "token" are insufficient for projects that interact with multiple third-party platforms, as they often use custom session cookie names.
**Prevention:** Maintain a comprehensive list of platform-specific sensitive keywords for masking and regularly audit the configuration keys used by the application.
