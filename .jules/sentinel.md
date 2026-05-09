## 2025-05-22 - Harden Configuration File Permissions
**Vulnerability:** Configuration files and directories were created with default permissions (often 0o644 or 0o755), which allowed other users on the same system to read sensitive tokens and cookies.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. It does not modify permissions if the file already exists.
**Prevention:** Always use an explicit `os.chmod` after file or directory creation to ensure restrictive permissions (0o600 for files, 0o700 for directories) are enforced even when overwriting existing files.
