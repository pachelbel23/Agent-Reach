## 2025-05-14 - Sensitive Data Leakage and Insecure File Permissions
**Vulnerability:** Platform-specific session identifiers (e.g., 'ct0', 'SESSDATA') were not masked in configuration dictionaries, and configuration files could retain broad permissions if created outside the application.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files; it does not modify permissions of an existing file. Explicit `os.chmod` is necessary to ensure restricted access for pre-existing files.
**Prevention:** Always use explicit `os.chmod` after file operations that require restricted permissions, and maintain a comprehensive list of sensitive keywords for data masking that includes platform-specific tokens.
