# Sentinel's Journal

## 2026-10-25 - SSRF Filter Bypass via IPv4-Embedded IPv6 Literals
**Vulnerability:** `normalize_public_http_url` relied solely on `ipaddress.IPv6Address.is_global` to reject private or loopback IP addresses. In Python's `ipaddress` standard library, IPv4-compatible (`::a.b.c.d`), IPv4-translated (`::ffff:0:a.b.c.d`), and NAT64 (`64:ff9b::a.b.c.d`) IPv6 addresses return `is_global == True` even when the embedded IPv4 address is loopback (`127.0.0.1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or link-local/cloud metadata (`169.254.169.254`).
**Learning:** Checking `.is_global` on an `IPv6Address` does not inspect embedded IPv4 addresses. Attackers can bypass SSRF filters targeting localhost or cloud metadata services by supplying IPv4-compatible or translated IPv6 representations (e.g., `http://[::127.0.0.1]/` or `http://[64:ff9b::169.254.169.254]/`).
**Prevention:** For any IPv6 address literal, unpack embedded IPv4 mappings (including IPv4-mapped, 6to4, Teredo, IPv4-compatible, IPv4-translated, and NAT64 well-known prefixes) and explicitly verify that the embedded IPv4 address is globally routable (`embedded.is_global`).
