## 2025-05-15 - Insecure File Permissions on Overwrite
**Vulnerability:** Loose file permissions (e.g., 644) on configuration files containing secrets, even when using `os.open` with restricted mode flags.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. If the file already exists, it preserves existing (potentially insecure) permissions.
**Prevention:** Always use an explicit `os.chmod` after opening or writing to a sensitive file to ensure restricted permissions (e.g., 600) are enforced regardless of the file's previous state.
