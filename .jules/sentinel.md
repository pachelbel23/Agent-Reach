## 2025-05-16 - Sensitive Identifier Masking Gaps
**Vulnerability:** Incomplete masking of platform-specific session identifiers (e.g., 'ct0' for Twitter, 'sessdata' for Bilibili) in configuration dictionaries.
**Learning:** Generic security masking keywords like 'key', 'token', 'password' failed to capture the variety in platform-specific session naming conventions, leading to potential data leakage in logs or UI.
**Prevention:** Maintain an extensible list of sensitive identifiers and implement robust masking that handles short secrets (using a fixed-length string) to avoid leaking length or prefix information.

## 2025-05-16 - Insecure Permissions on Existing Files
**Vulnerability:** Configuration files and directories could remain world-readable if they were created with broad permissions before the application enforced security.
**Learning:** `os.open` with `O_CREAT` and a mode bitmask correctly sets permissions for *new* files but does not modify permissions of an *existing* file.
**Prevention:** Always call `os.chmod` explicitly (wrapped in platform checks) after opening or creating sensitive files and directories to ensure the intended restricted state (e.g., 0o600 for files, 0o700 for directories) is enforced regardless of previous state.
