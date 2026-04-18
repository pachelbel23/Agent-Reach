## 2025-03-24 - Strengthening Configuration Permissions
**Vulnerability:** Configuration files and directories could be created with overly permissive permissions (e.g., world-readable), and existing files might retain insecure permissions even if overwritten using `os.open` with a mode bitmask.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask sets permissions only for NEW files. If the file already exists, its permissions remain unchanged. An explicit `os.chmod` is required to ensure restrictive permissions on every save.
**Prevention:** Always use `os.chmod` after creating or updating sensitive files to enforce the desired permission state (e.g., `0o600` for files, `0o700` for directories).
