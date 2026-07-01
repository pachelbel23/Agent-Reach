## 2025-05-22 - Explicit Permission Enforcement on Config Overwrite
**Vulnerability:** Weak file permissions on configuration files containing sensitive credentials (API keys, cookies) when the file already exists.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only applies permissions if the file is being newly created. If the file already exists, its permissions remain unchanged, potentially leaving sensitive data accessible to other users on the system if it was previously created with broader permissions (e.g., 0o644).
**Prevention:** Always use an explicit `os.chmod(path, mode)` after opening or writing to a sensitive file to ensure restrictive permissions (e.g., 0o600) are enforced regardless of the file's prior state.

## 2025-05-22 - Platform-Specific Secret Masking
**Vulnerability:** Data leakage of platform-specific session identifiers (e.g., `ct0`, `sessdata`, `jct`) in configuration exports and logs.
**Learning:** Generic security masking keywords (like 'key', 'token', 'password') often fail to capture the variety of session-naming conventions used by different platforms. Furthermore, short secrets might be accidentally exposed if the masking logic only targets longer strings or uses a fixed-length prefix.
**Prevention:** Maintain an extensible list of platform-specific sensitive identifiers for sanitization logic. Always mask the entire string (e.g., using asterisks) for short values instead of showing a prefix, to avoid leaking partial information.
