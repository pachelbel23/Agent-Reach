"""Security helpers for untrusted URLs."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

_BLOCKED_PUBLIC_FETCH_HOSTS = {
    "home.arpa",
    "instance-data",
    "internal",
    "ip6-localhost",
    "ip6-loopback",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "metadata.google.internal",
}
_BLOCKED_PUBLIC_FETCH_SUFFIXES = (
    ".home.arpa",
    ".internal",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
)


def _literal_ip_address(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse canonical and legacy IPv4 literal spellings without DNS."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    return ipaddress.IPv4Address(packed)


def _is_public_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject non-global IP addresses, including IPv4 addresses embedded in IPv6."""
    if not addr.is_global:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None and not addr.ipv4_mapped.is_global:
            return False
        raw = int(addr)
        prefix = raw >> 32
        # Check IPv4-compatible (::/96), IPv4-translated (::ffff:0:0/96), and NAT64 (64:ff9b::/96)
        if prefix in (0, 0xFFFF0000, 0x0064FF9B << 64):
            return ipaddress.IPv4Address(raw & 0xFFFFFFFF).is_global
    return True


def normalize_public_http_url(url: str) -> str:
    """Normalize a URL or reject targets that are not clearly public HTTP(S)."""
    candidate = str(url or "").strip()
    if (
        not candidate
        or "\\" in candidate
        or any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in candidate
        )
    ):
        raise ValueError("only public HTTP(S) URLs are allowed")
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
        # Accessing the port rejects malformed or out-of-range authorities.
        _ = parsed.port
    except (TypeError, ValueError):
        raise ValueError("only public HTTP(S) URLs are allowed") from None

    literal_address = _literal_ip_address(host)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or "%" in host
        or host in _BLOCKED_PUBLIC_FETCH_HOSTS
        or host.endswith(_BLOCKED_PUBLIC_FETCH_SUFFIXES)
        or ("." not in host and literal_address is None)
        or (literal_address is not None and not _is_public_ip(literal_address))
    ):
        raise ValueError("only public HTTP(S) URLs are allowed")

    return parsed.geturl()


def domain_matches(host: str, *domains: str) -> bool:
    """Match a hostname/cookie domain exactly or as a real subdomain."""
    normalized_host = str(host or "").lower().lstrip(".").rstrip(".")
    if not normalized_host:
        return False
    for domain in domains:
        allowed = domain.lower().lstrip(".").rstrip(".")
        if normalized_host == allowed or normalized_host.endswith("." + allowed):
            return True
    return False


def host_matches(url: str, *domains: str) -> bool:
    """Return whether *url* has an exact allowed host or a real subdomain.

    Only HTTP(S) URLs without userinfo are accepted. Using ``hostname`` rather
    than substring matching prevents lookalikes such as ``x.com.evil.test`` and
    userinfo disguises such as ``x.com@evil.test``.
    """
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        # ``hostname`` is permissive: malformed or out-of-range ports only
        # raise when ``port`` is accessed. Force that validation here so
        # hostile authorities fail closed.
        _ = parsed.port
    except (TypeError, ValueError):
        return False

    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    if not host or parsed.username is not None or parsed.password is not None:
        return False

    return domain_matches(host, *domains)
