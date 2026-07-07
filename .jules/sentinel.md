## 2025-05-15 - [Sensitive Data Leakage and Insecure Config Permissions]
**Vulnerability:** Configuration data masking failed to capture platform-specific session identifiers (ct0, sessdata, jct, etc.), and `Config.save()` did not enforce restrictive permissions on pre-existing files.
**Learning:** `os.open` with `O_CREAT` and mode bits only sets permissions for *newly created* files. For existing files, an explicit `os.chmod` is required to ensure security. Also, masking logic must include an exhaustive list of sensitive identifiers used by integrated platforms.
**Prevention:** Always explicitly enforce file permissions during save operations for sensitive files. Maintain an extensible list of sensitive keywords for data sanitization.
