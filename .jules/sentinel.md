## 2025-05-22 - [Sensitive Data Leakage in Config Masking]
**Vulnerability:** Incomplete masking of platform-specific session identifiers (e.g., 'ct0' for Twitter, 'sessdata' for Bilibili) in configuration dictionaries used for display/logging.
**Learning:** Generic masking keywords like 'token' or 'key' may miss platform-specific identifiers that carry equal or greater sensitivity (e.g., session cookies that bypass MFA).
**Prevention:** Maintain a centralized, comprehensive list of sensitive keywords that includes all platform-specific session tokens discovered during integration.
