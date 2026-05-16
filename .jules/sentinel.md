## 2026-05-16 - [CRITICAL/HIGH] Fix sensitive data leakage in config masking
**Vulnerability:** Incomplete masking of platform-specific session identifiers (e.g., 'ct0' for Twitter, 'sessdata' for Bilibili) in configuration dictionaries.
**Learning:** Masking logic must comprehensively cover all known platform-specific credential keys, not just generic terms like 'key' or 'token'.
**Prevention:** Maintain a centralized list of sensitive keywords and ensure all new platform integrations add their credential keys to this list.
