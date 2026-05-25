## 2025-05-25 - Secure Configuration and Data Masking

**Vulnerability:** Sensitive configuration data (like Twitter ct0, Bilibili sessdata) was not being masked in `to_dict()` output, and configuration directory/file permissions were not strictly enforced on existing files.

**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. If the file already exists, its permissions remain unchanged. Explicit `os.chmod` is required to ensure restrictive permissions on existing files/directories.

**Prevention:** Always use explicit `os.chmod` after file/directory operations where security is paramount. Use a comprehensive list of sensitive keywords for data masking and a fixed-length mask to avoid leaking secret lengths.
