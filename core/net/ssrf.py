"""SSRF-oriented helpers for platform-owned HTTP fetches.

These controls apply to code this repository owns (e.g. HeadersAdapter).
They do not govern Shannon/Briar browser or worker egress.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse, urlunparse


def require_http_url(url: str) -> tuple[str, str]:
    """Return (scheme, hostname) or raise ValueError for non-http(s)/hostless URLs."""
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http(s) URLs are allowed")
    if not parsed.hostname:
        raise ValueError("URL is missing a hostname")
    if parsed.username or parsed.password:
        # Credentials in URLs are supported for redaction elsewhere; host must still be valid.
        pass
    return parsed.scheme, parsed.hostname.lower()


def is_loopback_hostname(host: str | None) -> bool:
    if not host:
        return False
    h = host.strip().lower().rstrip(".")
    if h in {"localhost", "localhost."}:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return h == "::1" or h == "[::1]"


def is_non_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for loopback, private, link-local, multicast, reserved, unspecified."""
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (getattr(ip, "is_site_local", False))
    )


def _hostname_is_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip().lower().removeprefix("[").removesuffix("]"))
    except ValueError:
        return None


def validate_resolved_target(url: str, *, allow_non_public_literal: bool = True) -> None:
    """Resolve hostname and refuse DNS→non-public pivots for named hosts.

    IP literals that are non-public are allowed only when allow_non_public_literal
    is true (scope engine must have already authorized them).
    """
    scheme, host = require_http_url(url)
    parsed = urlparse(url.strip())
    port = parsed.port or (443 if scheme == "https" else 80)

    literal = _hostname_is_ip_literal(host)
    if literal is not None:
        if is_non_public_ip(literal) and not allow_non_public_literal:
            raise PermissionError(f"Refusing non-public IP literal target: {literal}")
        return

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise PermissionError(f"DNS resolution failed for {host}: {exc}") from exc

    if not infos:
        raise PermissionError(f"DNS resolution returned no addresses for {host}")

    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if is_non_public_ip(ip):
            # Named host resolved to a non-public address — classic SSRF/DNS rebinding path.
            if is_loopback_hostname(host) and ip.is_loopback:
                continue
            raise PermissionError(
                f"Refusing target {host!r}: resolved to non-public address {ip}. "
                "Authorize an IP/CIDR literal in the scope registry for private targets."
            )


_EMBEDDED_USERINFO_RE = re.compile(
    r"(?i)\b(https?://)([^/\s\"']+@)",
)


def redact_url_userinfo(value: str) -> str:
    """Remove userinfo from absolute or embedded http(s) URLs."""
    text = value or ""
    if "://" not in text:
        return text
    # Fast path for whole-string URLs
    try:
        parsed = urlparse(text.strip())
    except ValueError:
        parsed = None
    if parsed and parsed.scheme in {"http", "https"} and parsed.netloc and "@" in parsed.netloc:
        hostport = parsed.netloc.rsplit("@", 1)[-1]
        text = urlunparse(parsed._replace(netloc=hostport))
    # Also strip userinfo from URLs embedded in free text
    return _EMBEDDED_USERINFO_RE.sub(r"\1", text)
