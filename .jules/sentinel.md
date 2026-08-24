## 2025-02-24 - `os.open` creation mode mask does not alter existing file permissions
**Vulnerability:** Updating configuration files with `os.open` using `O_CREAT | O_TRUNC` and mode `0o600` fails to restrict permissions on existing files created with broader permissions (e.g., `0o644` or `0o666`).
**Learning:** `os.open` mode bits apply only to new file creation; truncating an existing file retains its original mode.
**Prevention:** Always call `os.chmod(file_path, 0o600)` explicitly on non-Windows platforms after file creation/opening to ensure existing files are updated to restricted permissions.
