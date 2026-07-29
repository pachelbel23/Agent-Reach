## 2026-03-20 - Sensitive Data Masking & Secure Configuration Permissions
**Vulnerability:** Weak substring masking of sensitive keywords in config exports allowed credentials (like `ct0`, `sessdata`, `csrf`, `jct`, and `cookie`) to leak in CLI logs/MCP exports. Slicing short secrets (<8 chars) leaked the prefix and total length of the secret. In addition, existing config files overwritten by `save()` did not have their permissions restricted to `0o600` because `os.open` with `O_CREAT` only sets permissions during initial file creation.
**Learning:**
1. Substring-based masking must use a comprehensive, extensible dictionary of keywords for platform-specific tokens. Slicing string values of unknown lengths for masking risks disclosing the entire value or its size if shorter than the slice length.
2. File creation masks using `os.open` do not alter permissions of pre-existing files on Unix-like operating systems. An explicit `os.chmod` is necessary to restrict permissions on overwrites.
**Prevention:**
1. Maintain a complete, case-insensitive keyword list for sensitive inputs, and secure short secret masking with a fixed-length mask (e.g., `****`).
2. Always apply explicit directory permission restriction (`0o700`) and file permission restriction (`0o600`) inside configuration management APIs, using cross-platform safe checks (`os.name != 'nt'`).
