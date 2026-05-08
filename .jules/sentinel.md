## 2025-05-19 - [Incomplete Sensitive Data Masking]
**Vulnerability:** Configuration dictionaries returned by `to_dict()` leaked platform-specific session identifiers (e.g., `ct0`, `sessdata`) and revealed too much of short secrets by revealing the first 8 characters.
**Learning:** Generic sensitive keywords like 'key' or 'token' are insufficient when integrating with various platforms that use bespoke session identifiers. Masking logic that reveals a fixed prefix can fully disclose short secrets.
**Prevention:** Maintain a centralized, comprehensive list of platform-specific sensitive keywords. Use a "mask-all" approach for short values (e.g., `********` for length ≤ 8) and minimize the revealed prefix for longer values (e.g., 4 characters).
