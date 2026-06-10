# Sentinel Journal

## 2025-05-14 - Incomplete masking of platform-specific secrets
**Vulnerability:** The `Config.to_dict()` method only masked keys containing "key", "token", "password", or "proxy". Platform-specific session identifiers like `ct0` (Twitter), `sessdata` (Bilibili), and `jct` (Bilibili) were left in plaintext in the dictionary representation, potentially leaking credentials in logs or debug output.
**Learning:** Generic filters for "key" or "token" are insufficient when integrating with multiple platforms that use non-standard names for session identifiers or secrets.
**Prevention:** Maintain a centralized list of sensitive keywords and proactively add platform-specific identifiers as new integrations are added.
