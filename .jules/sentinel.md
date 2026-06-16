## 2026-06-16 - [Incomplete Sensitive Data Masking]
**Vulnerability:** Platform-specific session identifiers (e.g., 'ct0', 'sessdata', 'jct') were not masked in configuration exports, potentially leaking credentials in logs.
**Learning:** Generic keyword matching (key, token, etc.) missed service-specific secret keys used by Twitter and Bilibili.
**Prevention:** Maintain a comprehensive list of sensitive keywords including platform-specific identifiers and use case-insensitive substring matching for masking.

## 2026-06-16 - [Insecure File Permissions on Overwrite]
**Vulnerability:** Configuration files could remain world-readable if they existed before the application attempted to set secure permissions during a save operation.
**Learning:** 'os.open' with 'O_CREAT' and a mode bitmask only sets permissions for *newly created* files; it does not modify permissions of existing files.
**Prevention:** Always use an explicit 'os.chmod' after writing sensitive files to ensure restricted permissions (0o600) regardless of the file's prior state.
