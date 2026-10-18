"""Shared destination policy for the egress gateway (stdlib-only).

This module is copied into ``docker/egress-gateway/`` at image build time so the
slim proxy container does not need the full platform package. Keep imports
limited to the Python standard library.

Architecture note
-----------------
Docker ``Internal=true`` networks are the primary boundary that blocks direct
internet when clients ignore ``HTTP(S)_PROXY``. The egress gateway applies
*destination-level* authorization only for proxied flows:

- empty allowlist → deny all proxied destinations
- allowlisted host → resolve; refuse non-public / metadata answers (DNS rebinding)
- optional port allowlist (default 80/443)

This is **not** transparent interception and does **not** wrap browser sockets
that ignore proxy variables — those remain blocked by Internal networks.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Callable
from typing import Iterable

DEFAULT_ALLOWED_PORTS: frozenset[int] = frozenset({80, 443})

# Cloud / link-local metadata and other always-prohibited destinations even if
# somehow returned by DNS for an allowlisted name.
_EXTRA_PROHIBITED_NETS = (
    "169.254.169.254/32",  # AWS/GCP/Azure IMDS (IPv4)
    "169.254.170.2/32",  # AWS ECS task metadata
    "fd00:ec2::254/128",  # AWS IMDS IPv6
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "2001:db8::/32",
)


def parse_allow_hosts(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip()}


def parse_allow_ports(raw: str | None, *, default: Iterable[int] = DEFAULT_ALLOWED_PORTS) -> set[int]:
    if raw is None or raw.strip() == "":
        return set(default)
    ports: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not (1 <= port <= 65535):
            raise ValueError(f"invalid proxy allow port: {port}")
        ports.add(port)
    return ports or set(default)


def load_allow_hosts_from_env(env_key: str = "PEN_PROXY_ALLOW_HOSTS") -> set[str]:
    return parse_allow_hosts(os.environ.get(env_key, "") or "")


def load_allow_ports_from_env(env_key: str = "PEN_PROXY_ALLOW_PORTS") -> set[int]:
    return parse_allow_ports(os.environ.get(env_key))


def is_prohibited_resolved_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for private/loopback/link-local/metadata/documentation addresses."""
    if bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or bool(getattr(ip, "is_site_local", False))
    ):
        return True
    for net in _EXTRA_PROHIBITED_NETS:
        if ip in ipaddress.ip_network(net):
            return True
    return False


ResolveFn = Callable[..., list]


def resolve_addresses(
    host: str,
    port: int,
    *,
    resolver: ResolveFn | None = None,
) -> list[str]:
    resolver = resolver or socket.getaddrinfo
    infos = resolver(host, port, type=socket.SOCK_STREAM)
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def evaluate_destination(
    host: str,
    port: int,
    *,
    allow_hosts: set[str] | None = None,
    allow_ports: set[int] | None = None,
    resolver: ResolveFn | None = None,
) -> tuple[bool, str, list[str]]:
    """Decide a proxied connection and return the addresses that were approved.

    Callers must connect to one of the returned addresses. Resolving the name
    again at connect time would reopen a DNS-rebinding window.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False, "missing host", []

    ports = allow_ports if allow_ports is not None else load_allow_ports_from_env()
    if port not in ports:
        return False, f"port {port} not in PEN_PROXY_ALLOW_PORTS ({sorted(ports)})", []

    hosts = allow_hosts if allow_hosts is not None else load_allow_hosts_from_env()
    if not hosts:
        return False, "PEN_PROXY_ALLOW_HOSTS is empty (deny by default)", []
    if host not in hosts:
        return False, f"host {host!r} not in PEN_PROXY_ALLOW_HOSTS", []

    try:
        literal = ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
    except ValueError:
        literal = None
    if literal is not None:
        if is_prohibited_resolved_ip(literal):
            return False, f"literal address prohibited: {literal}", []
        return True, "ok", [str(literal)]

    try:
        ips = resolve_addresses(host, port, resolver=resolver)
    except socket.gaierror as exc:
        return False, f"DNS failed: {exc}", []
    if not ips:
        return False, "DNS returned no addresses", []

    for ip_s in ips:
        ip = ipaddress.ip_address(ip_s)
        if is_prohibited_resolved_ip(ip):
            return False, f"resolved to non-public {ip}", []
    return True, "ok", ips


def decide_proxy_destination(
    host: str,
    port: int,
    *,
    allow_hosts: set[str] | None = None,
    allow_ports: set[int] | None = None,
    resolver: ResolveFn | None = None,
) -> tuple[bool, str]:
    """Decide whether the egress gateway may open an upstream connection.

    Returns ``(allowed, reason)``. Fail closed on missing/empty allowlist,
    disallowed ports, DNS failure, or any prohibited resolved address.
    """
    allowed, reason, _ips = evaluate_destination(
        host,
        port,
        allow_hosts=allow_hosts,
        allow_ports=allow_ports,
        resolver=resolver,
    )
    return allowed, reason


def evaluate_redirect_hops(
    hops: list[tuple[str, int]],
    *,
    allow_hosts: set[str] | None = None,
    allow_ports: set[int] | None = None,
    resolver: ResolveFn | None = None,
) -> tuple[bool, str]:
    """Require every hop of a proxied redirect chain to pass destination policy.

    This covers clients that honor the proxy and request each Location through it.
    A browser that ignores proxy settings is not intercepted here.
    """
    if not hops:
        return False, "redirect chain is empty"
    for host, port in hops:
        allowed, reason, _ips = evaluate_destination(
            host,
            port,
            allow_hosts=allow_hosts,
            allow_ports=allow_ports,
            resolver=resolver,
        )
        if not allowed:
            return False, f"redirect hop denied: {reason}"
    return True, "ok"
