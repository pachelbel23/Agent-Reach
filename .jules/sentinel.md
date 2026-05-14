## 2025-05-22 - Improved Sensitive Data Masking
**Vulnerability:** `Config.to_dict()` revealed the first 8 characters of sensitive values (keys, tokens, etc.) and missed several platform-specific session identifiers.
**Learning:** Partially masking secrets is insecure as it leaks entropy. Incomplete keyword lists for masking lead to accidental leakage of session cookies and CSRF tokens.
**Prevention:** Always use full masking (e.g., `********`) for secrets. Regularly audit and update the list of sensitive keywords to include new platform-specific identifiers.
