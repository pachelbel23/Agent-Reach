## 2025-05-22 - [Permission Enforcement Persistence]
**Vulnerability:** Sensitive configuration data leakage via overly permissive file/directory permissions.
**Learning:** `os.open` with a mode bitmask (e.g., `0o600`) only applies during file creation. If the file already exists, it retains its original permissions. Relying solely on `os.open` creates a race condition or a persistent vulnerability if the user or a previous process created the file with broader permissions.
**Prevention:** Always use explicit `os.chmod` calls after directory creation and file saving on Unix-like systems to enforce the principle of least privilege (0o700 for config directories, 0o600 for config files).
