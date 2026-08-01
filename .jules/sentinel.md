## 2026-07-31 - [Config Masking and Secure File Operations]
**Vulnerability:** Sensitive credentials could be exposed in multiple ways:
1. In `Config.to_dict()`, platform-specific session identifiers (like `ct0`, `sessdata`, `csrf`, `cookie`, `jct`) were not masked, and short credentials (less than 8 characters) were fully leaked due to prefix slicing.
2. In `Config.save()`, overwriting an existing config file that had broader permissions did not reduce its permissions since `os.open` with `O_CREAT` only sets permissions on newly created files.
3. In `_sync_xfetch_session`, sensitive files and folders were created using default permissions (often world-readable) before `os.chmod` was called, creating a race window.

**Learning:**
1. Generic security masking keywords do not capture the variety of platform-specific session naming conventions, and prefix-based masking leaks short secrets.
2. `os.open` with `O_CREAT` and a mode bitmask does not modify permissions of an existing file; an explicit `os.chmod` is required to ensure restrictive permissions on overwrites.
3. Restrictive directory creation (`0o700`) and the use of `os.open` with restricted permission bits during file creation prevent temporary exposure of sensitive keys.

**Prevention:**
1. Implement a comprehensive list of sensitive keywords for case-insensitive masking, and use a fixed-length `****` mask for short secrets to hide prefix/length details.
2. Always pair `os.open` file-creation flags with explicit `os.chmod(..., 0o600)` calls on Unix systems to securely lower permissions on pre-existing files.
3. Enforce `0o700` permissions on parent credential directories and `0o600` on credentials files from the moment of creation.
