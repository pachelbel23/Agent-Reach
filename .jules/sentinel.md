# Sentinel Journal

## 2025-05-15 - Incomplete masking of platform-specific session identifiers
**Vulnerability:** The `Config.to_dict()` masking logic only covered a few generic keywords ('key', 'token', 'password', 'proxy'), leaving platform-specific identifiers like `ct0` (Twitter), `sessdata`, `csrf`, `jct` (Bilibili), and generic `cookie` or `secret` keys exposed in logs or UI.
**Learning:** Security identifiers vary across platforms and may not use standard naming conventions. A whitelist of generic keywords is insufficient.
**Prevention:** Maintain a comprehensive `SENSITIVE_KEYWORDS` list that includes platform-specific session identifiers and common secret-related terms.

## 2025-05-15 - Race condition and persistence of loose file permissions
**Vulnerability:** File permissions were only set during creation with `os.open`. If a file already existed with looser permissions (e.g., 0o644), subsequent saves would not correct them.
**Learning:** `os.open` with `O_CREAT` and mode bits doesn't affect existing files. Explicit `os.chmod` is necessary to ensure restricted permissions (0o600) are maintained throughout the file's lifecycle.
**Prevention:** Always use explicit `os.chmod` after file operations that handle sensitive data to ensure intended restricted access.
