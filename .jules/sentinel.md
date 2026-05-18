## 2025-05-22 - Platform-Specific Secret Leakage in Masking
**Vulnerability:** Incomplete masking of platform-specific session identifiers (ct0, sessdata, csrf) in `Config.to_dict()`, and partial leakage of secrets by revealing the first 8 characters.
**Learning:** Generic sensitive keywords (key, token, password) often miss platform-specific identifiers used by scrapers or third-party APIs. Masking only the tail of a secret still leaks prefix information.
**Prevention:** Maintain a comprehensive list of platform-specific sensitive keywords and use a fixed mask string (e.g., `********`) that does not reveal any part of the original value or its length.
