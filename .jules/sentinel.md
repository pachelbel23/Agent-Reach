# Sentinel's Journal

## 2026-03-30 - `os.open` with `O_CREAT` does not enforce permissions on existing files
**Vulnerability:** Pre-existing configuration file `config.yaml` created with permissive bits (e.g., `0o644`) retained its group/world readable permissions even after `Config.save()` wrote sensitive credentials using `os.open` with mode `0o600`.
**Learning:** `os.open` mode bits only apply upon file creation; existing files retain their existing file mode on Unix systems.
**Prevention:** Always call `os.chmod(path, 0o600)` explicitly when writing or updating configuration files containing credentials or tokens.
