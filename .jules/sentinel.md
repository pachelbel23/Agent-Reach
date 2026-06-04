## 2025-05-22 - [Permission Enforcement on Existing Files]
**Vulnerability:** Weak file permissions on configuration files containing secrets (API keys, cookies).
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. If the file already exists with broader permissions (e.g., 0o644), `os.open` will not restrict them.
**Prevention:** Always call `os.chmod(path, 0o600)` explicitly after opening or writing to a file that must be restricted, to ensure permissions are corrected even on overwrites.
