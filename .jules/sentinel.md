## 2025-05-22 - [Harden] Sensitive Data Masking and Permission Enforcement
**Vulnerability:** Incomplete masking of platform-specific session identifiers (ct0, sessdata, jct) and potential for insecure configuration directory/file permissions on multi-user systems.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files; it does not modify permissions of an existing file. An explicit `os.chmod` is necessary to ensure restricted permissions on overwrites.
**Prevention:** Always use explicit `os.chmod` for critical configuration files and directories. Use a centralized list of sensitive keywords for consistent masking across the application.
