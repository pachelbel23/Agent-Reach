# Sentinel Journal 🛡️

## 2025-05-22 - Improved Sensitive Data Masking and Config Security
**Vulnerability:** Partial exposure of secrets in `Config.to_dict()` and missing masking for platform-specific tokens (`ct0`, `sessdata`, `jct`). Also, configuration file permissions were only enforced at creation, not during every save, potentially leaving existing files world-readable if manually modified.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only applies to new files; it does not modify permissions of an existing file. An explicit `os.chmod` is necessary to ensure defense-in-depth for sensitive configuration files.
**Prevention:** Use a centralized `SENSITIVE_KEYWORDS` constant for masking logic. Always explicitly enforce restrictive file permissions (0o600) on sensitive data files during every write operation.
