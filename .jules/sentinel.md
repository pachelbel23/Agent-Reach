## 2026-10-25 - SSRF Filter Bypass via IPv4-Embedded IPv6 Addresses
**Vulnerability:** In Python's standard `ipaddress` module, `IPv6Address.is_global` evaluates to `True` for IPv4-compatible (`::a.b.c.d`), IPv4-translated (`::ffff:0:a.b.c.d`), and NAT64 (`64:ff9b::a.b.c.d`) addresses even when the embedded IPv4 address is non-global (e.g., `127.0.0.1` or `10.0.0.1`), allowing SSRF protections to be bypassed.
**Learning:** `ipaddress.IPv6Address` only exposes `ipv4_mapped` for `::ffff:a.b.c.d`. Other IPv4-embedding IPv6 schemes require unpacking the embedded 32-bit IPv4 address integer representation to check `.is_global`.
**Prevention:** Always unpack embedded IPv4 addresses from IPv6 addresses using bit shifts (`int(addr)`) when validating untrusted URLs against SSRF.
