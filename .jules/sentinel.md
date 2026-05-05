## 2025-05-21 - Fix sensitive data leakage in config masking

**Vulnerability:** Incomplete masking of platform-specific tokens (ct0, sessdata) and full exposure of short secrets (8 chars or less) in `Config.to_dict()`.

**Learning:** Generic keyword matching ("key", "token") missed specific identifiers like `ct0` used by Twitter/X and `sessdata` used by Bilibili. Furthermore, the original masking logic always showed the first 8 characters, which leaked short secrets entirely.

**Prevention:** Maintain an exhaustive list of platform-specific sensitive keywords. Use a "mask-first" approach for short values (<= 8 characters) to ensure no part of the secret is exposed.
