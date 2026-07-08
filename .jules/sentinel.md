## 2025-05-15 - Incomplete masking of platform-specific secrets
**Vulnerability:** Configuration data leakage via `Config.to_dict()` which only masked keys containing "key", "token", "password", or "proxy", leaving platform-specific identifiers like `ct0` (Twitter) or `sessdata` (Bilibili) exposed in debug logs or output.
**Learning:** Generic security masking lists often fail to account for the diversity of session naming conventions across different platforms. Also, prefix-based masking (showing first 8 chars) can fully reveal short secrets.
**Prevention:** Maintain an extensible list of platform-specific sensitive identifiers and implement conservative masking for short values (e.g., fixed-length mask for values <= 8 characters).
