# Sentinel's Security Journal

## 2026-03-30 - IPv6 Embedded IPv4 Address Validation Bypass in SSRF Filter
**Vulnerability:** Python's standard `ipaddress.IPv6Address.is_global` property returns `True` for IPv4-compatible (`::a.b.c.d`), IPv4-translated (`::ffff:0:a.b.c.d`), and NAT64 (`64:ff9b::a.b.c.d`) IPv6 addresses even if the embedded IPv4 address is private or loopback (e.g. `127.0.0.1`, `10.0.0.1`, `169.254.169.254`). Only `::ffff:a.b.c.d` (IPv4-mapped) was marked non-global by `is_global` because standard libraries treat the others as globally routable prefixes, enabling SSRF protections to be bypassed.
**Learning:** `addr.ipv4_mapped` only captures standard IPv4-mapped addresses (`::ffff:x.x.x.x`). To properly validate IPv6 addresses embedding IPv4 targets, check the 96-bit prefix using integer bit shifting (`(val >> 32) in (0, 0xFFFF0000, 0x0064FF9B0000000000000000)`) and inspect the 32-bit embedded IPv4 address's `is_global` status.
**Prevention:** Always explicitly unpack and test embedded IPv4 addresses in any URL/IP SSRF filter before trusting an IPv6 address as global.
