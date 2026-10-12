"""Operator-facing isolation policy loaded from environment / config."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _truthy(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class IsolationPolicy:
    """Controls that wrap live Shannon/Briar/headers remote execution."""

    # Live remote tools must pass destination evaluation (DNS + non-public policy).
    require_egress_policy: bool = True
    # Block named hosts that resolve to non-public addresses (DNS rebinding class).
    block_non_public_resolved: bool = True
    # Allow IP-literal loopback/private only when scope already authorized them.
    allow_non_public_literals: bool = True
    # Disabling PEN_REQUIRE_SCOPE also needs this second gate.
    allow_scope_disable: bool = False
    # Shannon workers are NOT attached to platform Compose networks; live runs need
    # an explicit operator acknowledgement beyond launch-time DNS preflight.
    allow_shannon_live: bool = False
    # Host-invoked Briar CLI is NOT placed on Compose isolation networks; live runs
    # need an explicit operator acknowledgement beyond launch-time DNS preflight.
    allow_briar_live: bool = False
    # Optional explicit host allowlist (comma-separated). Empty = rely on scope registry.
    egress_allow_hosts: tuple[str, ...] = ()

    def host_allowlisted(self, host: str) -> bool:
        if not self.egress_allow_hosts:
            return False
        return host.strip().lower().rstrip(".") in self.egress_allow_hosts


def load_isolation_policy() -> IsolationPolicy:
    allow_hosts_raw = os.environ.get("PEN_EGRESS_ALLOW_HOSTS", "") or ""
    hosts = tuple(
        h.strip().lower().rstrip(".")
        for h in allow_hosts_raw.split(",")
        if h.strip()
    )
    return IsolationPolicy(
        require_egress_policy=_truthy("PEN_REQUIRE_EGRESS_POLICY", True),
        block_non_public_resolved=_truthy("PEN_BLOCK_NON_PUBLIC_RESOLVED", True),
        allow_non_public_literals=_truthy("PEN_ALLOW_NON_PUBLIC_LITERALS", True),
        allow_scope_disable=_truthy("PEN_ALLOW_SCOPE_DISABLE", False),
        allow_shannon_live=_truthy("PEN_ALLOW_SHANNON_LIVE", False),
        allow_briar_live=_truthy("PEN_ALLOW_BRIAR_LIVE", False),
        egress_allow_hosts=hosts,
    )
