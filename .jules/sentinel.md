## 2025-05-22 - [Sensitive Data Masking and Permission Hardening]
**Vulnerability:** Incomplete masking of platform-specific session identifiers (e.g., 'ct0' for Twitter, 'sessdata' for Bilibili) in configuration dictionaries and overly broad configuration file/directory permissions.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask doesn't modify permissions of an existing file; an explicit `os.chmod` is required to ensure restrictive permissions on overwrites.
**Prevention:** Use a comprehensive list of sensitive keywords for masking and always enforce `0o700` for config directories and `0o600` for config files on each save/initialization.
