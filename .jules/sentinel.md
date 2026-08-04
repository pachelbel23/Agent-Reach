# Sentinel Security Journal

This is the Sentinel journal for critical security learnings, unexpected side effects, or reusable patterns.

## 2026-03-16 - Securing Existing Files and Overwrite Permissions
**Vulnerability:** Insecure file permissions during file updates/saves and credential synchronization. Creating files with `os.open` and `O_CREAT` mode bitmask only applies permissions (such as `0o600`) to newly created files, but does not modify permissions of existing files if they already existed with broader access (like `0o644`).
**Learning:** Python's `os.open` behavior is a mapping of the POSIX standard open system call. If the file is already present, the mode parameter is completely ignored.
**Prevention:** Always follow up `os.open` or file creation operations with an explicit `os.chmod` call on non-Windows platforms to enforce owner-only read/write permissions (`0o600` or `0o700` for directories).
