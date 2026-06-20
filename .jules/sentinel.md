## 2025-05-22 - Incomplete Platform-Specific Secret Masking
**Vulnerability:** The `Config.to_dict()` method only masked keys containing generic terms like "key", "token", "password", or "proxy", leading to the leakage of platform-specific session identifiers such as `twitter_ct0` or `bilibili_sessdata` in logs and diagnostic reports.
**Learning:** Generic security masking patterns often fail to account for the variety of naming conventions used by different platforms for session and authentication data.
**Prevention:** Maintain a centralized, extensible list of sensitive keywords that includes specific identifiers for all integrated platforms (e.g., `ct0`, `sessdata`, `jct`, `csrf`) and ensure this list is used for all data sanitization tasks.
