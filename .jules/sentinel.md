## 2025-05-22 - [Permission Enforcement with os.open]
**Vulnerability:** Insecure file permissions (644 instead of 600) on configuration files containing sensitive cookies and tokens.
**Learning:** Using `os.open` with `O_CREAT` and a mode bitmask only sets the permissions for *newly created* files. If the file already exists, its permissions remain unchanged.
**Prevention:** Always call `os.chmod` explicitly after saving a file if strict permissions must be guaranteed, even on existing files.
