## 2025-06-15 - Insufficient Masking of Platform-Specific Secrets
**Vulnerability:** Platform-specific session identifiers (e.g., 'ct0' for Twitter, 'sessdata' for Bilibili) were not included in the 'to_dict()' masking logic, leading to potential data leakage in logs or diagnostics.
**Learning:** Masking logic based on generic keywords like 'key' or 'token' is insufficient for applications that handle specialized authentication tokens from third-party platforms.
**Prevention:** Maintain a comprehensive `SENSITIVE_KEYWORDS` list in the configuration management class and use more aggressive masking (e.g., percentage-based truncation) to protect short session identifiers.

## 2025-06-15 - os.open with O_CREAT and Mode Bitmask Limitation
**Vulnerability:** Files created with `os.open(..., O_CREAT, 0o600)` would not have their permissions updated if the file already existed with broader permissions (e.g., 0o644).
**Learning:** `os.open` mode bitmask only applies to new file creation. It does not enforce permissions on existing files.
**Prevention:** Always call `os.chmod` explicitly after saving or ensuring a directory exists to guarantee restricted permissions (0o700 for directories, 0o600 for files) on Unix systems.
