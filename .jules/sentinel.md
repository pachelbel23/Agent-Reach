## 2025-05-22 - Enhanced Sensitive Data Masking and Config Directory Permissions
**Vulnerability:** Information leakage of session-specific tokens (Twitter `ct0`, Bilibili `SESSDATA`, cookies) and potentially insecure configuration directory permissions.
**Learning:** Initial masking logic in `Config.to_dict()` focused only on generic keywords like 'key' or 'token', missing platform-specific sensitive identifiers. The configuration directory was created without explicit permission restrictions, relying on default system umask which could be too permissive.
**Prevention:** Always use a comprehensive list of sensitive keywords for masking in diagnostic outputs. Explicitly set restrictive permissions (`0o700` for directories, `0o600` for files) when handling sensitive credential storage.
