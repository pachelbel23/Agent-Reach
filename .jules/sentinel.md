# Sentinel Security Journal

## 2025-03-27 - Masking Sensitive Platform Credentials
**Vulnerability:** Accidental leakage of sensitive platform-specific credentials (e.g., `ct0` for Twitter, `sessdata` for Bilibili) in configuration reports or logs.
**Learning:** Generic masking keywords like `key` or `token` are insufficient when platforms use non-standard names for sensitive authentication data.
**Prevention:** Maintain an explicit list of platform-specific sensitive keywords (`ct0`, `sessdata`, `csrf`, `cookie`) in the configuration masking logic and update it when adding new platform integrations.
