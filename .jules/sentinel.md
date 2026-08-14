## 2026-07-28 - Masking Sensitive Keywords and Short Secrets in Config.to_dict()
**Vulnerability:** `Config.to_dict()` did not include platform-specific credential keywords (`cookie`, `sessdata`, `csrf`, `ct0`, `jct`, `secret`, `auth`) in its sensitive keyword list, and string slicing `str(v)[:8]` leaked short secret values (< 8 chars) in full.
**Learning:** Generic credential keyword matching fails to mask platform-specific token and cookie names. Additionally, slicing strings with `[:8]` on values shorter than 8 characters returns the entire string unmodified.
**Prevention:** Always maintain an extensible list of platform credential keywords for config masking and explicitly handle short secrets with a fixed-length mask string (e.g., `****`).
