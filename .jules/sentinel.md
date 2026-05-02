## 2025-05-14 - Hardened Configuration Security

**Vulnerability:** Configuration file and directory had default permissions, potentially allowing other local users to read sensitive API tokens and cookies. Additionally, the masking logic was insufficient, potentially leaking short secrets or missing platform-specific identifiers like 'sessdata' or 'ct0'.

**Learning:** `os.open` with `O_CREAT` and a mode bitmask doesn't modify permissions of an existing file; an explicit `os.chmod` is required to ensure restrictive permissions on overwrites. Masking should be case-insensitive and account for common session identifier names across different platforms.

**Prevention:** Always use restrictive permissions (0o700 for dirs, 0o600 for files) for credential storage. Use a robust masking list and handle short values by full redaction to prevent partial leaks.
