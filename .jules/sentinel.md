## 2025-05-22 - Platform-Specific Session Identifier Leakage
**Vulnerability:** Configuration dictionaries (returned via `to_dict()`) were only masking generic terms like 'key' or 'token', but leaked platform-specific session identifiers such as Twitter's `ct0`, Bilibili's `sessdata`, and `jct`.
**Learning:** Security masking logic that relies on generic keywords fails to account for the diversity of platform-specific authentication naming conventions. Hardcoding a limited set of keywords leads to incomplete protection.
**Prevention:** Maintain an extensible and comprehensive list of sensitive identifiers (e.g., `SENSITIVE_KEYWORDS` constant) that covers both generic and platform-specific authentication tokens used across all supported integrations.
