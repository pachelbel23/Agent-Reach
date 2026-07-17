## 2025-02-14 - Permission Enforcement on File Overwrites
**Vulnerability:** File permissions restriction to owner-only read/write (`0o600`) via `os.open` with a mode bitmask was bypassed if the configuration file already existed with wider permissions (e.g., world-readable `0o644`).
**Learning:** `os.open` with `O_CREAT` only applies the mode bitmask when a new file is created. If the file already exists, the mode parameter is ignored, leaving existing insecure permissions intact.
**Prevention:** Always apply an explicit `os.chmod` after creating or writing to files on Unix-like environments to guarantee restrictive permissions are actively enforced.

## 2025-02-14 - Sensitive Config Token Masking Leakage
**Vulnerability:** Platform-specific session cookies/tokens (like `ct0` for Twitter/X, `sessdata` and `jct` for Bilibili, and `csrf` or general cookies) were not masked by generic key/token substring checks, resulting in credentials leaking into printed logs/configurations. Additionally, secrets shorter than 8 characters were partially leaked due to prefix slicing and appending ellipsis.
**Learning:** Standard masking keyword lists fail to cover platform-specific, custom session identifier naming schemes. Masking with simple slice-and-ellipsis leaks short secrets entirely or in part.
**Prevention:** Maintain an explicit, case-insensitive list of platform-specific secret keywords (e.g. `ct0`, `sessdata`, `csrf`, `jct`, `cookie`) and use a fixed-length mask (e.g., `****`) for any secrets below a minimum safe character length threshold.
