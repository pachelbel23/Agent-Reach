## 2025-05-15 - [CRITICAL/HIGH] Masking of Platform-Specific Session Identifiers
**Vulnerability:** Platform-specific session identifiers such as `ct0` (Twitter), `sessdata` and `bili_jct` (Bilibili) were not masked in the configuration output (`Config.to_dict`), leading to potential data leakage.
**Learning:** Generic sensitive keywords like 'key' or 'token' are insufficient to cover all platform-specific authentication data.
**Prevention:** Maintain a comprehensive list of sensitive keywords and implement a robust masking algorithm that hides a significant portion of the secret, especially for short strings.

## 2025-05-15 - [MEDIUM] Insecure Configuration Directory Permissions
**Vulnerability:** The configuration directory `~/.agent-reach` was created with default system permissions (e.g., 0o775), which could allow other users on the system to list files or access the directory.
**Learning:** Relying on default directory creation (`Path.mkdir`) does not guarantee restrictive permissions.
**Prevention:** Explicitly enforce `0o700` permissions on sensitive directories immediately after creation using `os.chmod`.
