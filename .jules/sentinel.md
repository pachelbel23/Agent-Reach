## 2026-10-25 - SSRF Protection for IPv4 Embedded in IPv6

**Vulnerability:** In Python's `ipaddress` module, `IPv6Address.is_global` evaluates to `True` for IPv4-compatible (`::/96`), IPv4-translated (`::ffff:0:0:0/96`), and Well-Known Prefix NAT64 (`64:ff9b::/96`) addresses even when the embedded IPv4 address points to private or loopback ranges (e.g. `127.0.0.1`, `10.0.0.1`). This allowed SSRF protections in `normalize_public_http_url` to be bypassed using IPv6-wrapped private IPv4 addresses.

**Learning:** Relying solely on `addr.is_global` for IPv6 addresses is insufficient when applications support IPv6-embedded IPv4 syntax. The embedded IPv4 address must be unpacked and tested separately for global reachability. Additionally, `mypy` does not define the private attribute `_ip` on `IPv6Address`, so `int(addr)` should be used to extract bits safely.

**Prevention:** Inspect the upper 96 bits of IPv6 addresses for known transition prefixes (IPv4-compatible `0`, IPv4-mapped `0xffff`, IPv4-translated `0xffff0000`, and NAT64 `0x64ff9b...`), unpack the lower 32 bits into an `IPv4Address`, and check `is_global` against the embedded address.
