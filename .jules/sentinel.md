## 2025-04-09 - [HIGH] Sensitive data leakage in config masking
**Vulnerability:** Platform-specific session identifiers (e.g., `ct0`, `SESSDATA`, `bili_jct`) and other credentials like `csrf` tokens and `cookie` strings were not masked in the `Config.to_dict()` method, leading to potential exposure in logs or debug output.
**Learning:** Generic keyword masking (e.g., `key`, `token`) is insufficient for applications that integrate multiple platforms with custom authentication headers/identifiers.
**Prevention:** Maintain a comprehensive list of platform-specific sensitive keywords for masking and ensure directory permissions are locked down (`0o700`) upon creation.
