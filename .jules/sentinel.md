## 2025-05-18 - Enforce chmod on pre-existing configuration file saves
**Vulnerability:** `os.open` with `O_CREAT` and `mode=0o600` only sets permissions when creating a new file. If `config.yaml` exists with open permissions (e.g. `0o644`), subsequent calls to `Config.save()` leave file permissions unchanged and world-readable.
**Learning:** `os.open` mode bits do not modify permissions on existing files in POSIX environments.
**Prevention:** Always call `os.chmod(path, 0o600)` explicitly after writing sensitive files on POSIX systems (`os.name != 'nt'`).
