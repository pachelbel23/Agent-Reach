## 2026-07-02 - Sensitive Identifier Leakage in Config Masking
**Vulnerability:** Generic security masking keywords failed to capture variety in platform-specific session naming conventions (e.g., `ct0` for Twitter, `sessdata` for Bilibili). Additionally, short secrets were partially exposed via prefix leakage.
**Learning:** Sanitization logic must maintain an extensible identifier list that covers all supported integration platforms and should completely mask short strings to prevent prefix leakage.
**Prevention:** Regularly audit `Config.to_dict()` when adding new platform integrations and ensure a fail-safe masking policy for short sensitive values.
