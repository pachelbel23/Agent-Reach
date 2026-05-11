## 2025-05-15 - [CRITICAL] `os.open` Permission Enforcement Limitation
**Vulnerability:** Configuration file permissions could remain overly permissive if the file already existed before `Config.save()` was called, despite using restrictive mode flags in `os.open`.
**Learning:** `os.open(..., O_CREAT, mode)` only applies the specified mode bitmask during the initial creation of the file. If the file already exists (e.g., created by another process or previously with broader permissions), `os.open` will not update its permissions.
**Prevention:** Always use an explicit `os.chmod(path, mode)` after opening or creating a file that requires strict permissions to ensure they are enforced regardless of the file's prior state.
