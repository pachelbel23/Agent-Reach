## 2026-03-16 - Ineffective Permission Enforcement on Existing Files
**Vulnerability:** File permission modifications were not enforced upon configuration overwrite or updates in `Config.save()` when using `os.open` if the file already existed with wider permissions (e.g., group or world-readable).
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only applies permission limits when newly creating a file; it does not modify the mode of an existing file. Consequently, credentials saved to an existing broader-permission file remained exposed.
**Prevention:** Always call `os.chmod` explicitly on POSIX systems to restrict file permissions to `0o600` on overwrites and ensure restrictive file states.

## 2026-03-16 - Data Leakage of Platform-Specific Session Identifiers
**Vulnerability:** Core configuration details and specific session identifiers (e.g., `ct0`, `sessdata`, `csrf`, `jct`, and `cookie`) were not covered by generic sensitivity masking keywords in `Config.to_dict()`, potentially leaking credentials in configuration dictionary outputs, logs, or diagnostic reports.
**Learning:** Generic substring checks (like "key", "token", "password", "proxy") are insufficient to capture domain-specific and platform-specific authentication details, which can vary widely.
**Prevention:** Maintain a comprehensive, case-insensitive list of security-sensitive keywords specific to the platform integrations and mask them, ensuring even short secrets are obfuscated with a fixed-length string to prevent prefix or length leaks.
