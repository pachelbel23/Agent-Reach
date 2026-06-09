## 2025-06-09 - Permission Enforcement on Existing Files
**Vulnerability:** Weak permissions on configuration files (e.g., 0o644) could persist even after attempting to save with restricted flags if the file already exists.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. If the file already exists, it keeps its original permissions.
**Prevention:** Always use an explicit `os.chmod(path, mode)` after writing to ensure the desired restrictive permissions are enforced on existing files.
