# Sentinel's Journal - Critical Security Learnings

## 2025-05-18 - [Sensitive Config Dict Redaction Gaps]
**Vulnerability:** `Config.to_dict()` sliced strings using `str(v)[:8]...` for masking. Any sensitive value shorter than 8 characters was completely exposed without truncation or masking. Additionally, platform-specific token and cookie key names like `twitter_ct0`, `bilibili_sessdata`, `bilibili_csrf`, and `bili_jct` were not recognized as sensitive keywords.
**Learning:** Generic key matching keywords like `"key"` or `"token"` miss platform-specific parameter names. Truncating short secrets with `[:8]` fails to redact values with length < 8.
**Prevention:** Mask values shorter than 8 chars with a fixed replacement string (`"****"`), and maintain an explicit keyword list including platform-specific cookie and CSRF tokens (`ct0`, `sessdata`, `csrf`, `jct`, `cookie`).
