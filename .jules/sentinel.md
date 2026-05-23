## 2025-05-21 - os.open and File Permissions
**Vulnerability:** Insecure file permissions (e.g., 0o644) on configuration files containing sensitive API keys and tokens.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. If the file already exists, `os.open` (even with `O_TRUNC`) does not modify its permissions.
**Prevention:** Always use an explicit `os.chmod(path, 0o600)` after file operations to ensure restrictive permissions are enforced even on overwrites or pre-existing files.
