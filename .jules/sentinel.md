## 2026-03-31 - Platform-Specific Session Token Masking Gap
**Vulnerability:** `Config.to_dict()` failed to mask platform-specific session cookie keys (e.g. `twitter_ct0`, `bilibili_sessdata`, `bilibili_csrf`, `xhs_cookie`, `bili_jct`), and exposed full secret values for keys shorter than 8 characters.
**Learning:** Generic credential keyword matching (e.g., `key`, `token`, `password`, `proxy`) missed platform-specific cookie names used by integration channels. Additionally, string slicing `val[:8]` exposed short secrets in their entirety.
**Prevention:** Include all channel cookie and session identifiers in sanitization keyword lists, and mask short secrets with a fixed-length mask (`****`) rather than partial string slicing.
