## 2026-03-16 - Hardening Masking Logic and Permission Enforcement

**Vulnerability:**
1. Incomplete configuration masking in `Config.to_dict()` exposed platform-specific session and authentication tokens (such as `ct0`, `sessdata`, `csrf`, `cookie`, and `jct`). It also leaked short secrets (less than 8 characters) because the truncation logic `str(v)[:8]` returned the entire short secret followed by `...` (e.g. `"1234..."` for `"1234"`).
2. Using `os.open` with `O_CREAT` and a permission mode bitmask to write configuration files did not restrict file permissions if the file already existed with broader access permissions.

**Learning:**
1. Generic masking keywords (like `"key"`, `"token"`, `"password"`, `"proxy"`) do not catch platform-specific tokens or cookies such as Twitter's `ct0`, Bilibili's `SESSDATA`/`bili_jct`, and XiaoHongShu's `xhs_cookie`. Furthermore, string slicing to mask secrets must explicitly handle secrets shorter than the slice length to avoid leaking them.
2. On Unix-like systems, `os.open(..., os.O_CREAT)` only sets file creation permissions when a new file is created; it does not alter the mode of an already existing file.

**Prevention:**
1. Always maintain a comprehensive, case-insensitive list of platform-specific secret keys, cookies, and tokens for masking.
2. Mask short sensitive values with a fixed-length mask (such as `"****"`) rather than slicing them, ensuring that neither the length nor the prefix of the secret is leaked.
3. Always call an explicit `os.chmod` on Unix-like platforms after file creation/modification to guarantee that file permissions are restricted to `0o600` on overwrites.
