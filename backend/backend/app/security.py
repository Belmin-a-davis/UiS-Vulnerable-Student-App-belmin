"""Small, dependency-free security helpers shared by the routes."""
import ipaddress
import socket
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# SQL LIKE helper
# ---------------------------------------------------------------------------

def like_pattern(q: str) -> str:
    """Escape LIKE wildcards so user input matches literally, then wrap with %...%.

    Used together with a *parameterised* query; the escaping only prevents users
    from injecting `%`/`_` wildcards, the parameter binding is what stops SQLi.
    """
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

class UnsafeURL(ValueError):
    pass


def _is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    # Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1) before judging it.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def validate_outbound_url(url: str, resolver=socket.getaddrinfo) -> str:
    """Validate a user-supplied URL for server-side fetching.

    Rules: http/https only, no embedded credentials, only ports 80/443, and the
    hostname must resolve exclusively to public (global) IP addresses. Loopback,
    RFC1918, link-local (cloud metadata 169.254.169.254), CGNAT, ULA etc. are
    all rejected. Returns the normalised URL or raises UnsafeURL.
    """
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURL("Only http and https URLs are allowed.")
    if not parsed.hostname:
        raise UnsafeURL("URL has no host.")
    if parsed.username or parsed.password:
        raise UnsafeURL("Credentials in URLs are not allowed.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise UnsafeURL("Invalid port.")
    if port not in (80, 443):
        raise UnsafeURL("Only ports 80 and 443 are allowed.")

    try:
        infos = resolver(parsed.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UnsafeURL("Host could not be resolved.")
    if not infos:
        raise UnsafeURL("Host could not be resolved.")
    for info in infos:
        if not _is_public_ip(info[4][0]):
            raise UnsafeURL("The destination is not a public internet address.")
    return parsed.geturl()
