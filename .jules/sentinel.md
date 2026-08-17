## 2025-08-17 - Atomic File Creation with Restricted Permissions for Credential Sync
**Vulnerability:** Standard `open(file, "w")` followed by `os.chmod(file, 0o600)` creates a file with default umask permissions before restricting it, leaving a window for local credential exposure.
**Learning:** `os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)` ensures file creation with `0o600` permissions from inception, and explicit `os.chmod` secures existing files.
**Prevention:** Always use atomic `os.open` flags for writing credential/session files, and restrict directory permissions (`0o700`).
