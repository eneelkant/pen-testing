"""Scanner execution isolation controls (platform-enforced boundaries)."""

from .policy import IsolationPolicy, load_isolation_policy
from .egress import (
    DestinationDecision,
    assert_live_destination_allowed,
    evaluate_destination,
    validate_redirect_destination,
)
from .briar_exec import (
    build_compose_briar_command,
    find_compose_dir,
    resolve_briar_exec_mode,
    rewrite_paths_for_compose,
)
from .network_assert import (
    NetworkIsolationStatus,
    assert_network_internal,
    compose_networks_must_be_internal,
    inspect_network,
    required_scanner_networks,
)

__all__ = [
    "DestinationDecision",
    "IsolationPolicy",
    "NetworkIsolationStatus",
    "assert_live_destination_allowed",
    "assert_network_internal",
    "build_compose_briar_command",
    "compose_networks_must_be_internal",
    "evaluate_destination",
    "find_compose_dir",
    "inspect_network",
    "load_isolation_policy",
    "required_scanner_networks",
    "resolve_briar_exec_mode",
    "rewrite_paths_for_compose",
    "validate_redirect_destination",
]
