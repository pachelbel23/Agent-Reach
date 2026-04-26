## 2024-04-26 - [Config File Permissions Persistence]
**Vulnerability:** Insecure file permissions (e.g., 0o644) on sensitive configuration files containing API keys and browser cookies.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. If the file already exists with broader permissions (e.g., 0o644), `os.open` will not restrict them.
**Prevention:** Always use an explicit `os.chmod(path, 0o600)` after opening or writing to the file to ensure restrictive permissions are enforced regardless of the file's prior state.
