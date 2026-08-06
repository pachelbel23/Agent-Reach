# Sentinel Security Journal

## 2026-03-16 - [Secure Twitter Session Syncing]
**Vulnerability:** Duplicated and race-condition-prone writing of sensitive Twitter credentials (authToken and ct0) to `~/.config/xfetch/session.json`. The code created `session.json` with default system permissions (allowing public/group read), and only afterwards tightened it using `os.chmod(..., 0o600)`.
**Learning:** File creation via the standard `open(..., "w")` does not allow specifying a restrictive mode mask in Python without relying on the current process umask. To securely write sensitive data without race windows, files must be opened using `os.open` with a specific mode like `stat.S_IRUSR | stat.S_IWUSR` and flags like `os.O_CREAT | os.O_WRONLY | os.O_TRUNC` before being converted to a standard file-like object with `os.fdopen`.
**Prevention:** Always use `os.open` with restrictive mode flags to create sensitive configuration/credential files from the very beginning, and enforce `0o700` permissions on parent directories containing sensitive sessions.
