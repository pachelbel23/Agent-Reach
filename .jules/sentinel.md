## 2025-05-22 - Sensitive Data Leakage in Config Masking

**Vulnerability:** Incomplete masking of platform-specific session identifiers (e.g., 'ct0', 'sessdata', 'jct') and exposure of short secrets (≤ 8 characters) in configuration dictionaries returned by `Config.to_dict()`.

**Learning:** Generic masking keywords like 'key' or 'token' are insufficient when platforms use non-standard naming for session identifiers. Furthermore, masking logic that displays the first 8 characters of a value will accidentally disclose the entire secret if it is 8 characters or shorter.

**Prevention:** Maintain an exhaustive list of sensitive keywords, including platform-specific ones. Harden masking logic to return a fixed string (e.g., '********') for any value that falls below a minimum length threshold to ensure no partial or full disclosure of short secrets.
