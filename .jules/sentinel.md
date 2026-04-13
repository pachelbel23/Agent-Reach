## 2025-03-24 - [CRITICAL] Sensitive Data Leakage in Config Dictionaries
**Vulnerability:** Platform-specific session identifiers (`ct0`, `sessdata`, `bili_jct`, etc.) were not included in the masking logic of `Config.to_dict()`, leading to potential leakage of active session tokens in logs or diagnostic outputs.
**Learning:** Generic keyword matching for "key" or "token" is insufficient for projects integrating multiple platforms with idiosyncratic session naming conventions.
**Prevention:** Maintain a comprehensive list of platform-specific sensitive keywords and ensure `to_dict()` implementations prioritize defense-in-depth by masking any identifier that could facilitate session hijacking.

## 2025-03-24 - [HIGH] Insecure Configuration File Permissions
**Vulnerability:** Configuration files containing sensitive tokens were created with default system permissions (often 0o644), making them readable by other users on multi-user systems.
**Learning:** `os.open` with restricted mode flags only applies to new files; it does not correct permissions for existing files that may have been created insecurely.
**Prevention:** Always explicitly call `os.chmod(path, 0o600)` after file operations to ensure restricted permissions are enforced, regardless of the file's prior state.
