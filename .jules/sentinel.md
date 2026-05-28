# Sentinel Journal

## 2025-05-22 - Permission Enforcement on Existing Files
**Vulnerability:** Weak permissions on configuration files could persist even if the code uses `os.open` with restrictive flags when overwriting.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions if the file is newly created. If the file already exists, its permissions remain unchanged even if they are broader than requested.
**Prevention:** Always use an explicit `os.chmod` after opening or writing to a file if specific restrictive permissions (like 600) are required, to ensure they are enforced regardless of the file's prior state.
