## 2026-07-09 - [Insecure File Permission Enforcement on Overwrite]
**Vulnerability:** Configuration files containing sensitive secrets (cookies, tokens) could remain world-readable if they were initially created with loose permissions, even if subsequent writes used `os.open` with a restrictive mode bitmask.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. If the file already exists, the mode is ignored, and the existing permissions are preserved.
**Prevention:** Always use an explicit `os.chmod(path, mode)` after writing to a file that must have restricted permissions to ensure enforcement regardless of the file's previous state.
