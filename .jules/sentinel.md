## 2025-05-15 - Insufficient credential protection and data leakage in config

**Vulnerability:**
1. Sensitive configuration data was partially masked in `to_dict()`, leaking the first 8 characters of secrets (e.g., API keys, tokens).
2. Several platform-specific sensitive identifiers (like `ct0` for Twitter, `sessdata` for Bilibili) were not included in the masking logic.
3. The configuration directory (`~/.agent-reach`) had default permissions (often `0o755`), allowing other users to list files.
4. While `os.open` was used with `0o600` during file creation, it did not enforce restrictive permissions if the file already existed with broader permissions.

**Learning:**
- Partial masking is often "security theater" and can leak significant entropy or even the full secret if it's short.
- `os.open` with `O_CREAT` and a mode bitmask only sets permissions for *newly created* files. It does not modify permissions of an existing file.
- Security diagnostics should verify the entire path to a secret, including the parent directory.

**Prevention:**
- Use a fixed-length mask (e.g., `********`) for all sensitive values to avoid leaking length or content.
- Maintain a comprehensive list of sensitive keywords that covers all platform-specific tokens.
- Explicitly call `os.chmod` on both the configuration directory (`0o700`) and the file (`0o600`) to ensure restrictive permissions regardless of the file's previous state.
- Update health checks (`doctor` command) to verify these permissions and alert the user if they are insecure.
