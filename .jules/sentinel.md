# Sentinel Security Journal

## 2025-05-20 - `os.open` Permission Pitfall on Pre-existing Files
**Vulnerability:** Pre-existing configuration file `config.yaml` created with permissive default permissions (e.g., `0o644`) retained its group/world readable permissions even after `Config.save()` overwrote it using `os.open` with `0o600`.
**Learning:** `os.open` with `O_CREAT` only applies mode bits upon creation of a new file. When overwriting an existing file, the file's existing mode bits remain intact.
**Prevention:** Always call `os.chmod(path, 0o600)` explicitly after opening or writing sensitive configuration files on Unix platforms to enforce restrictive permissions regardless of initial file state.
