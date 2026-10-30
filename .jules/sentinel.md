## 2026-03-31 - IPv6 Embedded IPv4 SSRF Filter Bypass

**Vulnerability:** `normalize_public_http_url` failed to reject IPv4-compatible (`::127.0.0.1`), IPv4-translated (`::ffff:0:127.0.0.1`), and NAT64 (`64:ff9b::127.0.0.1`) IPv6 literal addresses wrapping private or loopback IPv4 addresses.

**Learning:** Python's standard `ipaddress.IPv6Address.is_global` property evaluates to `True` for IPv4-compatible or IPv4-translated IPv6 addresses even if the embedded IPv4 address is non-global (such as loopback `127.0.0.1` or internal `10.0.0.1` / IMDS `169.254.169.254`).

**Prevention:** When checking if an `IPv6Address` is a public/global IP for SSRF filtering, explicitly extract embedded IPv4 addresses (from `ipv4_mapped`, IPv4-compatible `::/96`, IPv4-translated `::ffff:0:0/96`, and NAT64 `64:ff9b::/96`) and verify that the embedded `IPv4Address.is_global` is also `True`.
