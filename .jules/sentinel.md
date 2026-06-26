## 2025-05-22 - Incomplete Masking of Platform-Specific Tokens
**Vulnerability:** Data leakage of Twitter (`ct0`) and Bilibili (`sessdata`, `bili_jct`) credentials in configuration outputs (`to_dict`).
**Learning:** Generic security masking keywords (key, token, password) failed to capture platform-specific session identifiers used by upstream tools (xreach, yt-dlp).
**Prevention:** Maintain a centralized, extensible list of sensitive identifiers (`SENSITIVE_KEYWORDS`) in the `Config` class and ensure all platform-specific session identifiers are included in the masking logic.
