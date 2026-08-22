## 2026-03-31 - Sensitive Identifier Masking in Config.to_dict()
**Vulnerability:** Generic security masking keywords ('key', 'token', 'password', 'proxy') fail to capture platform-specific session and cookie identifiers (e.g., 'ct0', 'sessdata', 'csrf', 'cookie', 'jct'). Short secrets under 8 characters were also fully exposed when truncated with slice `[:8]`.
**Learning:** Config sanitization logic must maintain an explicit list of platform-specific sensitive identifiers and mask short secrets with a fixed-length string (`****`) to prevent credential leakage.
**Prevention:** Whenever new platform integration keys or cookies are added, ensure sensitive keywords in `Config.to_dict()` are updated and short secret lengths are handled securely.
