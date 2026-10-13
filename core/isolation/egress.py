"""Destination / egress evaluation for platform-owned launch gates.

These checks run in the orchestrator *before* Shannon/Briar subprocesses start.
They do **not** intercept DNS or sockets inside upstream engines after launch.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from core.isolation.policy import IsolationPolicy, load_isolation_policy
from core.net.ssrf import (
    is_loopback_hostname,
    is_non_public_ip,
    require_http_url,
    validate_resolved_target,
)
from core.scope import ScopeEngine, validate_redirect_stays_in_scope


@dataclass(frozen=True)
class DestinationDecision:
    allowed: bool
    reason: str
    hostname: str = ""
    resolved_ips: tuple[str, ...] = ()


def _resolve_ips(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def evaluate_destination(
    url: str,
    *,
    policy: IsolationPolicy | None = None,
    scope_engine: ScopeEngine | None = None,
    test_category: str = "active",
) -> DestinationDecision:
    policy = policy or load_isolation_policy()
    try:
        scheme, host = require_http_url(url)
    except ValueError as exc:
        return DestinationDecision(False, str(exc))

    parsed = urlparse(url.strip())
    port = parsed.port or (443 if scheme == "https" else 80)

    if policy.egress_allow_hosts and not policy.host_allowlisted(host):
        # Explicit allowlist mode: deny unless listed (still also need scope when provided).
        return DestinationDecision(
            False,
            f"Host {host!r} is not in PEN_EGRESS_ALLOW_HOSTS",
            hostname=host,
        )

    if scope_engine is not None:
        decision = scope_engine.evaluate(url, test_category=test_category)
        if not decision.allowed:
            return DestinationDecision(False, f"Scope denied: {decision.reason}", hostname=host)

    if not policy.block_non_public_resolved:
        return DestinationDecision(True, "Egress non-public checks disabled by policy", hostname=host)

    # Literal IPs: allow non-public only when configured (scope should have authorized).
    try:
        literal = ipaddress.ip_address(host.strip().removeprefix("[").removesuffix("]"))
    except ValueError:
        literal = None

    if literal is not None:
        if is_non_public_ip(literal) and not policy.allow_non_public_literals:
            return DestinationDecision(
                False,
                f"Non-public IP literal refused: {literal}",
                hostname=host,
                resolved_ips=(str(literal),),
            )
        return DestinationDecision(
            True,
            "IP literal accepted under policy",
            hostname=host,
            resolved_ips=(str(literal),),
        )

    try:
        ips = _resolve_ips(host, port)
    except socket.gaierror as exc:
        return DestinationDecision(False, f"DNS resolution failed for {host}: {exc}", hostname=host)

    if not ips:
        return DestinationDecision(False, f"DNS returned no addresses for {host}", hostname=host)

    for ip_str in ips:
        ip = ipaddress.ip_address(ip_str)
        if is_non_public_ip(ip):
            if is_loopback_hostname(host) and ip.is_loopback:
                continue
            return DestinationDecision(
                False,
                f"Host {host!r} resolved to non-public address {ip} (DNS rebinding / SSRF class risk)",
                hostname=host,
                resolved_ips=tuple(ips),
            )

    # Re-run shared helper for consistency / extra edge cases.
    try:
        validate_resolved_target(url, allow_non_public_literal=policy.allow_non_public_literals)
    except PermissionError as exc:
        return DestinationDecision(False, str(exc), hostname=host, resolved_ips=tuple(ips))

    return DestinationDecision(
        True,
        "Destination passed scope + resolve-time non-public checks",
        hostname=host,
        resolved_ips=tuple(ips),
    )


def assert_live_destination_allowed(
    url: str,
    *,
    policy: IsolationPolicy | None = None,
    scope_engine: ScopeEngine | None = None,
    test_category: str = "active",
    dry_run: bool = False,
) -> DestinationDecision:
    """Fail closed for live runs when egress policy is required."""
    policy = policy or load_isolation_policy()
    if dry_run:
        return DestinationDecision(True, "dry_run skips live egress enforcement")
    if not policy.require_egress_policy:
        # Dual gate: PEN_REQUIRE_EGRESS_POLICY=false alone is insufficient.
        if not policy.allow_egress_disable:
            raise PermissionError(
                "PEN_REQUIRE_EGRESS_POLICY is disabled but PEN_ALLOW_EGRESS_DISABLE is not set; "
                "refusing to weaken launch-time destination checks (operator dual-gate)."
            )
        return DestinationDecision(True, "PEN_REQUIRE_EGRESS_POLICY disabled with dual gate")
    decision = evaluate_destination(
        url,
        policy=policy,
        scope_engine=scope_engine,
        test_category=test_category,
    )
    if not decision.allowed:
        raise PermissionError(decision.reason)
    return decision


def validate_redirect_destination(
    base_url: str,
    location: str | None,
    *,
    policy: IsolationPolicy | None = None,
    scope_engine: ScopeEngine | None = None,
    test_category: str = "passive",
) -> tuple[bool, str]:
    """Same-origin check plus resolve-time policy on the redirect target."""
    ok, detail = validate_redirect_stays_in_scope(base_url, location)
    if not ok:
        return False, detail
    if not location:
        return True, detail
    from core.scope.target import resolve_redirect

    dest = resolve_redirect(base_url, location)
    # Same-origin already enforced. Re-check resolve-time non-public policy only —
    # do not require a second path-exact scope match for /login style redirects.
    _ = scope_engine  # reserved for future host-level scope binding
    decision = evaluate_destination(
        dest,
        policy=policy,
        scope_engine=None,
        test_category=test_category,
    )
    if not decision.allowed:
        return False, decision.reason
    return True, dest
