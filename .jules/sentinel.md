# Sentinel's Journal - Security Learnings

## 2025-05-18 - Generic Masking Keyword Gap in Config Export
**Vulnerability:** `Config.to_dict()` previously used a limited list of sensitive terms (`key`, `token`, `password`, `proxy`) and sliced strings as `str(v)[:8]...`. This leaked secrets shorter than 8 characters in full and missed platform-specific credential keywords (`ct0`, `sessdata`, `csrf`, `jct`, `cookie`, `auth`, `session`).
**Learning:** Short secret slicing (`str(v)[:8]`) leaks plaintext when `len(v) < 8`. In addition, generic security masking keywords fail to capture platform-specific session/cookie naming conventions.
**Prevention:** Always mask short secrets (< 8 chars) with a fixed length mask (`****`) and maintain an inclusive, extensible identifier list for session cookie parameters.
