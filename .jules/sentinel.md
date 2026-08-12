# Sentinel Journal

## 2026-03-09 - [File permissions and existing files security fix]
**Vulnerability:** `os.open` with `O_CREAT` and a mode bitmask (e.g. `stat.S_IRUSR | stat.S_IWUSR`) does not modify permissions of an existing file if the file already exists; an explicit `os.chmod` is required to ensure restrictive permissions on overwrites.
**Learning:** Overwriting files in Python using standard file operations or `os.open` without an explicit `os.chmod` can result in files retaining broader permissions if they were previously created with more relaxed settings.
**Prevention:** Always follow up file creation or overwrite operations with an explicit `os.chmod` on Unix-like systems when targeting secure file permissions (e.g., 0o600).
