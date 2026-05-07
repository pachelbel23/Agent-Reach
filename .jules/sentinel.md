## 2025-05-14 - Harden Config Permissions and Masking
**Vulnerability:** Incomplete masking of platform-specific tokens (ct0, sessdata) and potential for configuration files to remain world-readable if they existed before restrictive permissions were applied.
**Learning:** `os.open` with restrictive mode bits does not change the mode of an existing file; an explicit `os.chmod` is necessary to guarantee secure permissions on existing files.
**Prevention:** Always use `os.chmod` after file operations that require specific permission levels, especially when handling sensitive configuration data.
