## 2025-05-14 - Sensitive Data Leakage in Config Masking
**Vulnerability:** Configuration identifiers like `ct0`, `sessdata`, `jct`, and `cookie` were not masked in `Config.to_dict()`, leading to potential credential leakage in logs or MCP tool outputs. Additionally, short secrets were partially leaked because the masking logic always showed the first 8 characters.
**Learning:** Generic security masking keywords (key, token, password) often miss platform-specific session identifiers. Masking logic must account for varying lengths of sensitive data to avoid leaking the entire value for short secrets.
**Prevention:** Maintain an extensive list of sensitive keywords and use a fixed-length mask for secrets shorter than a certain threshold.
