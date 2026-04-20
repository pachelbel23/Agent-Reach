## 2025-05-23 - Hardening Config Permissions and Masking
**Vulnerability:** Incomplete masking of platform-specific identifiers (ct0, sessdata) and potential for insecure file permissions if config file was pre-existing.
**Learning:** `os.open` with `O_CREAT` and mode bits doesn't affect existing files; an explicit `os.chmod` is required to ensure restrictive permissions on Unix.
**Prevention:** Always use `os.chmod` after file creation/update for sensitive files, and maintain a comprehensive list of sensitive keywords for data masking.
