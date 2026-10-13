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
    # Disabling PEN_REQUIRE_EGRESS_POLICY also needs this second gate.
    allow_egress_disable: bool = False
    # Block named hosts that resolve to non-public addresses (DNS rebinding class).
    block_non_public_resolved: bool = True
    # Allow IP-literal loopback/private only when scope already authorized them.
    allow_non_public_literals: bool = True
    # Disabling PEN_REQUIRE_SCOPE also needs this second gate.
    allow_scope_disable: bool = False
    # Shannon workers are NOT attached to platform Compose networks; live runs need
    # an explicit operator acknowledgement beyond launch-time DNS preflight.
    allow_shannon_live: bool = False
    # Live Briar requires this gate in addition to an execution mode that can
    # place the process on a platform network (compose) or an explicit host-net ack.
    allow_briar_live: bool = False
    # Briar execution: compose (default, platform networks) or host (uncontained).
    briar_exec_mode: str = "compose"
    # Host-network Briar (PEN_BRIAR_EXEC=host) needs this second acknowledgement.
    allow_briar_host_net: bool = False
    # Optional explicit host allowlist (comma-separated). Empty = rely on scope registry.
    egress_allow_hosts: tuple[str, ...] = ()

    def host_allowlisted(self, host: str) -> bool:
        if not self.egress_allow_hosts:
            return False
        return host.strip().lower().rstrip(".") in self.egress_allow_hosts


def load_isolation_policy() -> IsolationPolicy:
    from core.isolation.briar_exec import resolve_briar_exec_mode

    allow_hosts_raw = os.environ.get("PEN_EGRESS_ALLOW_HOSTS", "") or ""
    hosts = tuple(
        h.strip().lower().rstrip(".")
        for h in allow_hosts_raw.split(",")
        if h.strip()
    )
    try:
        briar_mode = resolve_briar_exec_mode()
    except ValueError:
        # Fail closed to compose (safer default) if the env value is garbage; adapters
        # also validate and surface a clear error on live runs.
        briar_mode = "compose"
    return IsolationPolicy(
        require_egress_policy=_truthy("PEN_REQUIRE_EGRESS_POLICY", True),
        allow_egress_disable=_truthy("PEN_ALLOW_EGRESS_DISABLE", False),
        block_non_public_resolved=_truthy("PEN_BLOCK_NON_PUBLIC_RESOLVED", True),
        allow_non_public_literals=_truthy("PEN_ALLOW_NON_PUBLIC_LITERALS", True),
        allow_scope_disable=_truthy("PEN_ALLOW_SCOPE_DISABLE", False),
        allow_shannon_live=_truthy("PEN_ALLOW_SHANNON_LIVE", False),
        allow_briar_live=_truthy("PEN_ALLOW_BRIAR_LIVE", False),
        briar_exec_mode=briar_mode,
        allow_briar_host_net=_truthy("PEN_ALLOW_BRIAR_HOST_NET", False),
        egress_allow_hosts=hosts,
    )
