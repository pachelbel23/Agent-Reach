## 2025-05-22 - Sensitive session identifiers leakage in config dictionary
**Vulnerability:** Platform-specific session identifiers (e.g., 'ct0' for Twitter, 'sessdata' for Bilibili) were not being masked in the `Config.to_dict()` method, potentially leading to accidental exposure in logs or UI.
**Learning:** Generic keywords like 'token' or 'key' are insufficient when dealing with multiple platforms that use custom cookie/session names.
**Prevention:** Maintain a comprehensive list of platform-specific sensitive identifiers and ensure they are all included in the masking logic.

## 2025-05-22 - Incomplete filesystem permission enforcement
**Vulnerability:** The configuration file and directory were created with restricted permissions only on the first write/creation, but subsequent updates did not guarantee that permissions remained restricted if they were changed externally.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions if the file is being created. It does not modify permissions of an existing file.
**Prevention:** Use an explicit `os.chmod` after creating or modifying a sensitive file to ensure its permissions are always correctly restricted (e.g., 0o600 for files, 0o700 for directories).
