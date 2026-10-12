"""Scanner execution isolation controls (platform-enforced boundaries)."""

from .policy import IsolationPolicy, load_isolation_policy
from .egress import (
    DestinationDecision,
    assert_live_destination_allowed,
    evaluate_destination,
    validate_redirect_destination,
)

__all__ = [
    "DestinationDecision",
    "IsolationPolicy",
    "assert_live_destination_allowed",
    "evaluate_destination",
    "load_isolation_policy",
    "validate_redirect_destination",
]
