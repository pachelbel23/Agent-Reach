## 2025-04-08 - [Sensitive Data Masking and Permission Enforcement]
**Vulnerability:** Configuration directory was created with default permissions (potentially world-readable), and `to_dict()` masked only generic keys, leaving platform-specific session identifiers (e.g., `ct0`, `sessdata`) exposed in debug output.
**Learning:** Security depends on protecting both the data (masking) and the container (directory permissions). Generic security checks often miss platform-specific identifiers and directory-level risks.
**Prevention:** Always use exhaustive keyword lists for masking and enforce owner-only permissions for sensitive directories (`0o700`) and files (`0o600`).
