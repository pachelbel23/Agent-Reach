# Sentinel Security Journal

## 2026-10-25 - SSRF Protection Bypass via Embedded IPv4 in IPv6
**Vulnerability:** `IPv6Address.is_global` in Python's `ipaddress` module returns `True` for IPv4-compatible (`::/96`), IPv4-translated (`::ffff:0:0/96`), and NAT64 well-known prefix (`64:ff9b::/96`) addresses even when the embedded IPv4 address is non-global (e.g. `127.0.0.1`, `10.0.0.1`, `169.254.169.254`). This allowed bypassing SSRF validation in `normalize_public_http_url`.
**Learning:** Checking `.is_global` on an IPv6 address is insufficient if the address embeds an IPv4 address. Only IPv4-mapped (`::ffff:0:0/96`) evaluates `.is_global` properly in Python's standard library, while other RFC-defined embedded IPv4 formats do not.
**Prevention:** In URL and IP validation routines, explicitly inspect the upper 96 bits of IPv6 addresses for IPv4-compatible, IPv4-translated, and NAT64 prefixes, extract the embedded 32-bit IPv4 address, and ensure that embedded address is also verified with `.is_global`.
