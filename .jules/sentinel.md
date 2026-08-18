# Sentinel's Journal

## 2026-08-18 - Atomic Secure Session Creation for xfetch Credentials
**Vulnerability:** `_sync_xfetch_session` created `~/.config/xfetch/session.json` using standard `open()` before calling `os.chmod(..., 0o600)`, creating a window where credentials were briefly readable by other local processes. Additionally, `~/.config/xfetch` directory permissions were unconstrained.
**Learning:** Standard `open()` creates files using the process umask (typically `0644`), leading to potential secret leakage before deferred `os.chmod` execution.
**Prevention:** Always use `os.open()` with `os.O_CREAT | os.O_WRONLY | os.O_TRUNC` and explicit `stat.S_IRUSR | stat.S_IWUSR` (`0o600`) flags, and restrict parent directory permissions to `0o700`.
