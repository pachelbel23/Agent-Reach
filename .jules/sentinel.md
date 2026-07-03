# Sentinel Journal 🛡️

## 2025-05-18 - [Incomplete Masking of Platform-Specific Secrets]
**Vulnerability:** Configuration dictionaries were leaking short secrets (<= 8 characters) because the masking logic used `[:8]` slicing, which returns the original string if it is short. Additionally, many platform-specific session identifiers (e.g., `ct0`, `sessdata`, `jct`) were not being identified as sensitive.
**Learning:** Generic security masking keywords like "key" or "token" fail to capture the variety of platform-specific session naming conventions. Sanitization logic must be extensible and robust against short secrets.
**Prevention:** Maintain an extensible list of sensitive identifiers and use full asterisk masking for short values to avoid prefix leakage.
