## 2025-05-21 - os.open Mode Limitation on Existing Files
**Vulnerability:** File permissions for sensitive configuration data (`config.yaml`) could remain overly permissive (e.g., 0o644) if the file already existed, even when using `os.open` with a restricted mode bitmask (e.g., 0o600).
**Learning:** The mode argument in `os.open(path, flags, mode)` only applies when the file is being *created* (i.e., when `O_CREAT` is set and the file does not exist). If the file already exists, its permissions are not modified by `os.open`.
**Prevention:** Always use an explicit `os.chmod(path, mode)` after opening or writing to a file to ensure the desired restrictive permissions are enforced, regardless of the file's previous state.
