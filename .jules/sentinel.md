# Sentinel's Journal - Critical Security Learnings

## 2025-05-14 - os.open and Permission Enforcement
**Vulnerability:** Insecure file permissions on configuration files containing secrets.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask (e.g., `0o600`) only sets permissions if the file is *created*. If the file already exists with broader permissions (e.g., `0o644`), `os.open` (even with `O_TRUNC`) does *not* tighten them.
**Prevention:** Always use an explicit `os.chmod(path, 0o600)` after opening/writing a file that must be restricted, to ensure permissions are corrected even on existing files.

## 2025-05-14 - Sensitive Data Masking Completeness
**Vulnerability:** Sensitive data leakage in logs or diagnostic output.
**Learning:** Generic keywords like 'key' or 'token' are often insufficient to catch platform-specific session identifiers (e.g., 'ct0' for Twitter, 'sessdata' for Bilibili).
**Prevention:** Maintain a comprehensive list of sensitive keywords tailored to the application's integrations and ensure they are masked before any dictionary conversion for display or logging.
