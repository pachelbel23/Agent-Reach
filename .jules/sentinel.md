## 2025-04-12 - Sensitive Data Leakage and Insecure Permissions

**Vulnerability:** Platform-specific session identifiers (e.g., `ct0`, `sessdata`, `jct`) and cookies were not masked in configuration dictionaries, leading to potential credential leakage in logs or CLI output. Additionally, configuration directory permissions were not explicitly restricted to the owner.

**Learning:** Generic masking keywords like "key" or "token" are insufficient for projects that handle raw platform cookies or custom session identifiers. Security-sensitive directories should have their permissions enforced not only at creation but also corrected periodically (e.g., during save) to prevent accidental permission drift.

**Prevention:** Maintain a comprehensive list of platform-specific sensitive keywords for masking. Always use `os.chmod` or `os.open` with specific modes (`0o700`/`0o600`) to ensure configuration files remain private to the owner on multi-user systems.
