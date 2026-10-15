# Sentinel's Journal

## 2026-03-30 - Masking Short Secrets & Platform Cookie Identifiers
**Vulnerability:** `Config.to_dict()` exposed secrets shorter than 8 characters in full (e.g. `12345...`) and failed to recognize platform session cookies (e.g. `twitter_ct0`, `bilibili_sessdata`, `bili_jct`, `xhs_cookie`).
**Learning:** Slicing a secret string with `[:8]` when its length is less than 8 characters returns the full unmasked secret string. Platform-specific session token naming conventions (like `ct0`, `sessdata`, `csrf`, `jct`) are not captured by generic security keywords (`key`, `token`, `password`).
**Prevention:** Always check string length before prefix slicing and use a fixed string like `"****"` for short sensitive values. Keep an expanded list of platform-specific cookie and session identifier keywords.
