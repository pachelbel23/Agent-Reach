# Sentinel Journal

## 2025-05-22 - [HIGH] Incomplete Sensitive Data Masking in Config
**Vulnerability:** Platform-specific session identifiers (e.g., `ct0` for Twitter, `SESSDATA` for Bilibili) were not being masked in the `Config.to_dict()` output, potentially leaking credentials in logs or UI.
**Learning:** Generic keywords like 'key' or 'token' are insufficient when using third-party platform cookies where identifiers are non-standard.
**Prevention:** Maintain a comprehensive `SENSITIVE_KEYWORDS` list and use a constant-length mask (`********`) to prevent leaking the secret's length.
