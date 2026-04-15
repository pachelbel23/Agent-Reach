## 2025-05-14 - Configuration Permissions and Masking
**Vulnerability:** Incomplete masking of platform-specific session identifiers (e.g., 'ct0', 'sessdata') in configuration dictionaries and potentially overly broad file permissions on existing configuration files.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for newly created files; it does not change permissions if the file already exists.
**Prevention:** Explicitly use `os.chmod` after saving sensitive files and maintain a comprehensive list of platform-specific sensitive keywords for masking.
