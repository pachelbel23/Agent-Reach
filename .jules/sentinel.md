## 2025-05-22 - [Insecure File Permissions and Data Leakage in Config]
**Vulnerability:** The configuration file (`config.yaml`), which contains sensitive session cookies and API tokens, could retain overly permissive file permissions if it was created before the restrictive `os.open` call. Additionally, `Config.to_dict()` failed to mask platform-specific session identifiers like `ct0`, `sessdata`, and `jct`.

**Learning:** `os.open(path, os.O_CREAT | ..., mode)` only sets the mode if the file is *created*. If the file already exists, it does not change the permissions. Generic security masking keywords like 'key' and 'token' are insufficient for applications that handle platform-specific session data.

**Prevention:** Always call `os.chmod(path, 0o600)` explicitly after opening or writing a sensitive file on Unix-like systems to ensure its permissions are restricted. Maintain an extensible list of sensitive keywords that includes platform-specific identifiers.
