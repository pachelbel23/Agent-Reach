## 2025-05-15 - Hardening Config Permissions and Masking

**Vulnerability:** Configuration directory and files could have loose permissions (e.g., 0o775), potentially exposing sensitive cookies and API keys to other users on the system. Additionally, platform-specific identifiers like `ct0` or `sessdata` were not masked in the `to_dict()` output.

**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly* created files. If a file already exists with looser permissions, `os.open` will not correct them. An explicit `os.chmod` is necessary to ensure restricted permissions on every save.

**Prevention:** Always enforce strict permissions (0o700 for directories, 0o600 for files) using explicit `os.chmod` on configuration paths. Maintain a comprehensive list of platform-specific sensitive keywords for data masking logic.
