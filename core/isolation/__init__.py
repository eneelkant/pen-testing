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

__all__ = [
    "DestinationDecision",
    "IsolationPolicy",
    "assert_live_destination_allowed",
    "build_compose_briar_command",
    "evaluate_destination",
    "find_compose_dir",
    "load_isolation_policy",
    "resolve_briar_exec_mode",
    "rewrite_paths_for_compose",
    "validate_redirect_destination",
]
