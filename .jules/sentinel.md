## 2025-05-15 - Enforcing File Permissions on Existing Files
**Vulnerability:** Configuration files containing sensitive tokens (Twitter ct0, Bilibili SESSDATA, etc.) could persist with insecure permissions (e.g., 0o644) if they were created before the 0o600 enforcement was added or if they were manually edited. `os.open` with `O_CREAT` and a mode does not change permissions of an existing file.
**Learning:** To guarantee restrictive permissions on a file that may already exist, an explicit `os.chmod` call is necessary after opening or during the save process.
**Prevention:** Always use `os.chmod(path, 0o600)` after writing sensitive files to ensure they are not world-readable, regardless of their previous state.

## 2025-05-15 - Leakage of Short Sensitive Values
**Vulnerability:** The masking logic `f"{str(v)[:8]}..."` leaked the entire value if the secret was shorter than 8 characters (e.g., a 4-character PIN or short token). It also lacked keywords for common platform-specific session identifiers like `ct0`, `jct`, and `sessdata`.
**Learning:** Masking logic must account for string length and use a fixed-length mask for short values to avoid leaking the original content or its length.
**Prevention:** Use a check for minimum length before slicing, and maintain an exhaustive list of sensitive keywords including platform-specific ones.
