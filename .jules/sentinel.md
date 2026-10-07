## 2026-03-30 - Session Cookie Masking & Secure Credential Synchronization

**Vulnerability:**
Config.to_dict() failed to mask platform session cookies (e.g., `twitter_ct0`, `bilibili_sessdata`, `xhs_cookie`) and completely exposed short secrets (<8 chars) in plain text. Additionally, Twitter credential sync to `~/.config/xfetch/session.json` created files and directories with default umask permissions before setting `os.chmod`, leaving credentials briefly world-readable.

**Learning:**
Generic security masking keywords (like 'key' or 'token') fail to capture domain-specific cookie names (e.g., 'ct0', 'sessdata'). Standard file creation via `open()` creates files using system umask before `os.chmod()` executes, creating a race condition window where secrets are exposed.

**Prevention:**
Maintain an explicit list of platform cookie identifiers for config masking, mask short secrets completely with fixed strings, and create credential files/directories using `os.open` with restrictive mode bitmasks (`0o600` for files, `0o700` for directories) from inception.
