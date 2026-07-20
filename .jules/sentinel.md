# Sentinel's Security Journal 🛡️

## 2026-07-20 - Enforcing Config Permissions and Platform Masking
**Vulnerability:** Configuration files loaded/saved via Config class could exist with overly-broad permissions if created outside the app. Moreover, platform-specific credentials (like 'ct0' and 'sessdata') were not masked in the config output representation.
**Learning:** `os.open` with standard create flags does not adjust permissions of existing files on write/overwrite. Standard security keyword masking lists (like 'key', 'token') miss platform-specific identifiers used by integrated platforms.
**Prevention:** Use an explicit `os.chmod` call during config saves to force restrictive permissions even on overwrites, and maintain a robust, case-insensitive substring list of platform-specific credential keywords for masking.
