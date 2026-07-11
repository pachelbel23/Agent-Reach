# Sentinel Security Journal 🛡️

## 2025-05-15 - Explicit chmod required for existing sensitive files
**Vulnerability:** The configuration file `config.yaml` could remain world-readable even after a "secure" save if it was previously created with broad permissions.
**Learning:** `os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)` only sets the permission bits if the file is *created* during the call. If the file already exists, its permissions are preserved despite the mode argument.
**Prevention:** Always use an explicit `os.chmod(path, 0o600)` after writing sensitive files to ensure permissions are restricted regardless of the file's prior state.

## 2025-05-15 - Platform-specific session identifiers missed by generic masking
**Vulnerability:** Critical session tokens like `ct0` (Twitter) and `sessdata` (Bilibili) were being leaked in plaintext by `Config.to_dict()` because the masking logic only looked for generic keywords like `key` or `token`.
**Learning:** Generic security identifiers fail to capture the variety of session management implementations across different platforms.
**Prevention:** Maintain an extensible list of platform-specific sensitive identifiers and verify masking with dedicated regression tests.
