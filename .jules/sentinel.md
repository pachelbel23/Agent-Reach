## 2025-03-24 - [CRITICAL] Sensitive Data Leakage in Masking Logic and Insecure Permissions

**Vulnerability:**
1.  **Sensitive Data Leakage:** The `Config.to_dict()` method was missing several platform-specific sensitive identifiers (like `ct0` for Twitter, `sessdata` for Bilibili) from its masking list. This could lead to session tokens being logged or displayed in plain text if `to_dict()` is used for debugging or reporting.
2.  **Insecure File Permissions:** The configuration directory and file were created with default system permissions (often `0o775` or `0o755`), potentially making sensitive cookies and API keys readable by other users on the same system.

**Learning:**
- Hardcoding a narrow list of sensitive keywords (e.g., just "key", "password") is insufficient for multi-platform tools where session identifiers have non-standard names like `ct0` or `bili_jct`.
- `os.open` with flags can create a file with correct permissions, but if the file already exists, it won't change them. An explicit `os.chmod` is safer for ensuring consistent security state.
- Automated tests should verify both the *behavior* of security features (masking) and the *state* of the environment (file permissions).

**Prevention:**
- Maintain a comprehensive list of sensitive keywords based on all integrated platform specifications.
- Use a dedicated security test suite (`tests/test_security_fixes.py`) to catch regressions in permission handling and data masking.
- Always enforce `0o700` for config directories and `0o600` for config files on Unix systems.
