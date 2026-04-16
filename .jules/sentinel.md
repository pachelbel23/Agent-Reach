## 2025-05-22 - Restricted File Permissions Persistence
**Vulnerability:** Configuration files containing sensitive tokens could retain overly permissive permissions (e.g., 0o644) if they already existed, even if `os.open` was called with `0o600` mode bits during a subsequent save.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. It does not modify permissions of an existing file.
**Prevention:** Always use an explicit `os.chmod(path, 0o600)` after file operations to ensure restrictive permissions are enforced regardless of the file's prior state.
