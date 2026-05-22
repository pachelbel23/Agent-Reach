## 2025-03-09 - [Secure configuration handling and masking]
**Vulnerability:** Sensitive data leakage in `Config.to_dict()` and potentially insecure file/directory permissions.
**Learning:** `os.open` with `O_CREAT` and mode bitmask does not change permissions of an existing file. Explicit `os.chmod` is needed to ensure restrictive permissions on overwrites. Masking should use a fixed string to avoid leaking secret length or prefix.
**Prevention:** Use `os.chmod` for both directory (0o700) and file (0o600) creation/updates. Maintain a comprehensive list of sensitive keywords for masking.
