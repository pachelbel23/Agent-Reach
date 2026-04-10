# Sentinel Security Journal

## 2025-05-15 - [HIGH] Incomplete Sensitive Data Masking in Configuration
**Vulnerability:** The `Config.to_dict()` method, used to display configuration status, only masked values containing 'key', 'token', 'password', or 'proxy'. Platform-specific session identifiers like 'ct0' (Twitter), 'sessdata' (Bilibili), and 'bili_jct' (Bilibili CSRF) were leaked in plaintext.
**Learning:** Security masking must account for all potential sensitive identifiers used across different integrations, especially when dealing with session-based authentication (cookies).
**Prevention:** Maintain a comprehensive list of sensitive keywords for masking and ensure new integrations add their session identifiers to this list.

## 2025-05-15 - [MEDIUM] Insecure Configuration Directory Permissions
**Vulnerability:** While the `config.yaml` file had restricted permissions (0o600), the parent directory `~/.agent-reach` was created with default system permissions. On multi-user systems, this could allow other users to list the directory contents, potentially exposing the existence of sensitive configuration files or other metadata.
**Learning:** Protecting the file itself is not enough; the containing directory should also have restricted permissions (0o700) to ensure complete isolation of sensitive data.
**Prevention:** Explicitly set directory permissions to 0o700 immediately after creation.
