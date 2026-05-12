# Sentinel Journal

## 2025-05-22 - Data Leakage and Permission Hardening
**Vulnerability:** Configuration data containing sensitive session identifiers (ct0, sessdata) was not being masked in `to_dict()`, and masked values leaked secret prefixes. Configuration directory permissions were not restricted.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only applies to new files; existing files need an explicit `os.chmod` to ensure restrictive permissions.
**Prevention:** Use a fixed masking string (`********`) for all sensitive data. Explicitly set directory (0o700) and file (0o600) permissions on Unix-like systems during creation and save operations.
