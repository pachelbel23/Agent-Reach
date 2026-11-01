# Sentinel's Journal

## 2026-11-01 - SSRF bypass via IPv6-embedded IPv4 addresses in ipaddress
**Vulnerability:** Python's standard `ipaddress` module evaluates `IPv6Address.is_global` as `True` for IPv4-compatible (`::a.b.c.d`), IPv4-translated (`::ffff:0:a.b.c.d`), and NAT64 (`64:ff9b::/96`) addresses even when the embedded IPv4 address points to private, loopback, or link-local destinations (such as `127.0.0.1` or `169.254.169.254`). Relying solely on `addr.is_global` allowed SSRF filter bypasses.
**Learning:** `ipaddress.IPv6Address` only checks IPv6 scope classifications and does not unpack embedded IPv4 payloads for global/private status except for `addr.ipv4_mapped` (`::ffff:a.b.c.d`).
**Prevention:** In URL and IP validation logic, explicitly inspect IPv6 addresses for embedded IPv4 encodings (IPv4-mapped, IPv4-compatible, IPv4-translated, and NAT64 prefixes), parse the trailing 4 bytes as `IPv4Address`, and check `is_global` on the unpacked IPv4 address.
