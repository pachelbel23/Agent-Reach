## 2025-05-22 - [Config Permission Enforcement]
**Vulnerability:** Insecure configuration file and directory permissions.
**Learning:** `os.open` with `O_CREAT` and mode bitmask does not modify permissions of an existing file. An explicit `os.chmod` is required to ensure restrictive permissions (0o600 for files, 0o700 for directories) on Unix-like systems, especially when overwriting existing files.
**Prevention:** Always follow up file creation/writing with an explicit `os.chmod` for sensitive files.

## 2025-05-22 - [Sensitive Data Masking Leakage]
**Vulnerability:** Partial masking of sensitive data (leaking first 8 characters) and incomplete keyword coverage.
**Learning:** Session identifiers like `ct0` (Twitter) and `sessdata` (Bilibili) are as sensitive as passwords but were not masked. Fixed-length masking (`********`) is superior to partial masking as it doesn't leak actual value length or prefixes.
**Prevention:** Use a comprehensive keyword list and a fixed-length mask for all sensitive dictionary outputs.
