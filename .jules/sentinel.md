## 2025-05-15 - Sensitive Data Leakage in Config Masking
**Vulnerability:** Incomplete masking of platform-specific session identifiers (e.g., 'ct0' for Twitter, 'sessdata' for Bilibili) in configuration dictionaries when using `to_dict()`.
**Learning:** Generic masking keywords like 'key' or 'token' are insufficient for modern web platforms that use unconventional session cookie names.
**Prevention:** Maintain a comprehensive list of platform-specific sensitive keywords and ensure short secrets are fully masked (e.g., using '********' for ≤ 8 chars) rather than partially exposed.
