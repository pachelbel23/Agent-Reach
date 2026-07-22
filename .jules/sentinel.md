## 2026-03-16 - File Permissions on Pre-Existing Configuration Overwrites
**Vulnerability:** Weak or world-readable permissions on sensitive configuration files when they pre-exist the application.
**Learning:** `os.open` with `os.O_CREAT` and a mode bitmask (e.g. `stat.S_IRUSR | stat.S_IWUSR` or `0o600`) restricts permissions ONLY if the file is newly created. If the file already existed with broader permissions (such as `0o644` or `0o666`), `os.open` does NOT modify the file's existing permissions on Unix-like systems. This leaves sensitive data vulnerable to local exposure.
**Prevention:** Always call `os.chmod` explicitly on the target file path after opening or saving to ensure the intended restrictive permissions (such as `0o600`) are permanently and reliably enforced.
