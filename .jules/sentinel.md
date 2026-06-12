## 2025-05-15 - Enhancing Sensitive Data Masking
**Vulnerability:** Incomplete masking of platform-specific session identifiers (e.g., 'ct0' for Twitter, 'sessdata' for Bilibili) in configuration dictionaries led to potential data leakage in logs or doctor reports.
**Learning:** Generic keywords like 'key' or 'token' are insufficient for applications integrating multiple platforms with proprietary session management.
**Prevention:** Use a comprehensive and centralized list of sensitive keywords for masking, including platform-specific identifiers like 'ct0', 'sessdata', and 'jct'.
