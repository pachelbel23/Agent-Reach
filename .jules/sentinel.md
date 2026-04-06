## 2025-05-22 - [Sensitive Data Leakage in Config Masking]
**Vulnerability:** Platform-specific session identifiers (e.g., `ct0`, `sessdata`, `csrf`, `cookie`) were not being masked in `Config.to_dict()`, leading to potential leakage of credentials in logs or health reports.
**Learning:** Generic keywords like `key`, `token`, `password`, and `proxy` are not sufficient when a project uses platform-specific cookie names as credentials.
**Prevention:** Maintain an explicit list of all sensitive keys used across all supported platforms (Twitter, Bilibili, XiaoHongShu, etc.) and ensure they are covered by the masking logic.
