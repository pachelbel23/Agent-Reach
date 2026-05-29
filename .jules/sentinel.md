# Sentinel Journal

## 2025-05-22 - [CRITICAL] Sensitive Data Leakage in Config Masking
**Vulnerability:** The `Config.to_dict()` method was leaking platform-specific session identifiers (e.g., `twitter_ct0`, `bilibili_sessdata`) because they didn't match the hardcoded keywords ("key", "token", etc.). Additionally, it leaked the first 8 characters of masked secrets.
**Learning:** Hardcoded, narrow keyword lists for masking are fragile and easily miss platform-specific authentication tokens. Partial masking (prefixing) is insecure and should be avoided in favor of full masking.
**Prevention:** Use a centralized, comprehensive `SENSITIVE_KEYWORDS` class constant that includes known platform tokens (`ct0`, `sessdata`, `csrf`, `jct`, `cookie`). Always use a fixed-length mask (e.g., `********`) to avoid leaking both the prefix and the actual length of the secret.
