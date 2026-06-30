## 2025-05-22 - Sensitive data leakage and insecure file permissions
**Vulnerability:**
1. `Config.to_dict()` did not mask platform-specific session identifiers like `ct0` (Twitter), `sessdata` (Bilibili), and `jct` (Bilibili), leading to potential credential leakage in logs or CLI output.
2. `Config.save()` used `os.open` with restrictive mode, which only applies to newly created files. Existing configuration files with broader permissions (e.g., 0o644) were not corrected to 0o600 upon saving.

**Learning:**
- Generic security masking keywords (key, token, etc.) are insufficient when platforms use non-standard session identifiers.
- `os.open` with `O_CREAT` and a mode bitmask does not change permissions of an existing file. An explicit `os.chmod` is necessary to ensure restrictive permissions on updates.

**Prevention:**
- Maintain a list of platform-specific sensitive identifiers for sanitization.
- Always explicitly enforce file permissions using `os.chmod` when handling sensitive data files on Unix-like systems.
