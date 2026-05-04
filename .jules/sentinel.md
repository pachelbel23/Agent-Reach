## 2025-05-20 - [HIGH] Hardened configuration security and data masking

**Vulnerability:**
1. Sensitive data leakage: The `Config.to_dict()` method truncated sensitive values to 8 characters. If a secret was 8 characters or shorter, it was disclosed in full in diagnostic reports.
2. Insecure file permissions: The configuration file `config.yaml` was created with default permissions (often 0644), making sensitive API keys and session cookies readable by other users on the system.

**Learning:**
1. `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly* created files. If the file already exists, it does NOT modify the permissions. An explicit `os.chmod` is required to ensure restrictive permissions on overwrites.
2. Masking logic using simple truncation (`val[:8] + '...'`) is dangerous for short secrets.

**Prevention:**
1. Always use explicit `os.chmod(path, 0o600)` for sensitive files and `0o700` for sensitive directories on Unix-like systems.
2. Ensure masking logic handles short values by returning a full mask (e.g., '********') instead of a truncated one.
