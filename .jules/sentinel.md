## 2025-05-22 - Sensitive Data Leakage in Config Masking
**Vulnerability:** Partial masking of sensitive credentials (leaking first 8 characters) and missing platform-specific identifiers (ct0, sessdata, jct).
**Learning:** Generic masking logic ('key', 'token') is insufficient for multi-platform tools where session identifiers have non-obvious names. Partial masking can reveal significant portions of short tokens.
**Prevention:** Use a centralized `SENSITIVE_KEYWORDS` list and enforce full, fixed-length masking for all sensitive fields. Add regression tests for all platform-specific secrets.
