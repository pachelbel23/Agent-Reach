# Sentinel Journal

## 2026-03-16 - Masking Extensibility & Explicit Permission Hardening

**Vulnerability:**
1. In `Config.to_dict()`, generic sensitive keywords (like `key`, `token`) failed to mask platform-specific session naming conventions such as `ct0`, `sessdata`, `csrf`, `cookie`, and `jct`. Furthermore, strings shorter than 8 characters would be partially leaked or append ellipsis due to simple slicing logic.
2. In `Config.save()`, utilizing `os.open` with a mode bitmask on an already existing configuration file failed to restrict permissions to `0o600` because the mode argument only applies to newly created files.

**Learning:**
1. Sanitization and masking logic must maintain an explicit, case-insensitive list of specific credentials and session identifiers mapped to upstream tools (like `xreach` and browser cookies), and always mask short secrets to a fixed string (e.g. `****`) to avoid leaking prefix or exact length.
2. `os.open` with `O_CREAT` and a mode bitmask does not modify permissions of an existing file; an explicit `os.chmod` is required to guarantee restrictive permissions on Unix-like systems.

**Prevention:**
Always implement explicit verification tests under `tests/test_security_fixes.py` verifying both short and long credential masking, and validating that file and folder permissions are set correctly on non-Windows environments.
