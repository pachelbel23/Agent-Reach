## 2025-06-25 - Masking of platform-specific session identifiers
**Vulnerability:** Generic security masking keywords (like 'key', 'token') fail to capture variety in platform-specific session naming conventions (e.g., 'ct0', 'sessdata'). This results in CRITICAL/HIGH data leakage in configuration logs or dictionary exports.
**Learning:** Platform-specific session identifiers often don't follow generic naming patterns, making them invisible to standard security filters. Sanitization logic must maintain an extensible identifier list.
**Prevention:** Regularly audit the set of sensitive keys across all integration channels and update the central configuration sanitization logic (`Config.to_dict`) to include them. Implement robust masking for short secrets to avoid entropy leakage.
