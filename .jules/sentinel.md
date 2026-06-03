## 2025-03-20 - Enforcing config file permissions
**Vulnerability:** Configuration files containing sensitive secrets (auth tokens, cookies) could be world-readable if they already existed with broad permissions, as `os.open` with mode flags does not change permissions of existing files.
**Learning:** In Python, `os.open(path, flags, mode)` only sets the mode for newly created files. If the file already exists, the `mode` argument is ignored. This creates a security gap where sensitive data can be leaked if a user or another process previously created the config file with insecure permissions.
**Prevention:** Always use an explicit `os.chmod(path, 0o600)` after writing sensitive configuration files on Unix-like systems to ensure restricted access regardless of the file's previous state.
