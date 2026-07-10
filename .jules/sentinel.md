## 2025-05-18 - Incomplete Sensitive Data Masking for Platform-Specific Tokens
**Vulnerability:** Configuration data masking in `Config.to_dict()` missed platform-specific sensitive identifiers like `ct0` (Twitter), `sessdata` (Bilibili), and `jct` (Bilibili). Additionally, sensitive values shorter than 8 characters were not masked at all due to slicing logic.
**Learning:** Generic security masking keywords (key, token, password) often fail to capture the variety in session management naming conventions across different platforms. Slicing-based masking needs a fallback for short strings to avoid data leakage.
**Prevention:** Maintain an extensible list of platform-specific sensitive identifiers. Use a fixed-length mask (e.g., `****`) for values shorter than the intended prefix length.
