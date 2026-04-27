## 2025-05-15 - [Sensitive Data Masking Improvement]
**Vulnerability:** CRITICAL/HIGH - Incomplete masking of platform-specific session identifiers (ct0, sessdata, csrf, cookie, auth, jct) in configuration dictionaries led to potential leakage of sensitive credentials in logs and reports.
**Learning:** Generic keywords like 'key' and 'token' are insufficient for modern platforms that use domain-specific session identifiers (e.g., 'ct0' for Twitter/X, 'sessdata' for Bilibili).
**Prevention:** Maintain a comprehensive list of known sensitive field names across all supported platforms and ensure they are all covered by the masking logic in `Config.to_dict()`.
