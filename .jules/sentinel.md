## 2026-07-24 - Credential Leakage & Weak Local File Permissions
**Vulnerability:** Platform-specific credentials (like ct0, sessdata, csrf, cookie, auth, and bili_jct) in configuration outputs were not fully masked, exposing sensitive session details. Shorter secrets (<8 chars) were fully leaked without masking, and local filesystem permissions were not tightly enforced.
**Learning:** Masking logic needs to be extensible to cover domain-specific session/cookie keys, and file creation modes via `os.open` only apply to newly created files; they do not adjust permissions of existing files on modification.
**Prevention:** Use domain-agnostic substrings and target platform spec keys for masking. Apply explicit `os.chmod` on both directory creation and config saving on non-Windows platforms.
