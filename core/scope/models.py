"""Authorization and scope record models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# Bumped when authorization evaluation semantics change in a breaking way.
SCOPE_POLICY_VERSION = "scope-engine-v2"


@dataclass
class AuthorizationRecord:
    program_name: str
    program_url: str
    target_id: str
    asset_type: str  # url | host | repo | cidr | other
    scope_source: str
    policy_reference: str
    allowed_assets: list[str]
    excluded_assets: list[str] = field(default_factory=list)
    allowed_test_categories: list[str] = field(default_factory=lambda: ["passive", "active"])
    prohibited_actions: list[str] = field(default_factory=list)
    rate_limit_rps: float | None = None
    authorization_start: str | None = None  # ISO-8601
    authorization_expiry: str | None = None  # ISO-8601
    environment: str = "staging"  # production | staging | sandbox | local
    notes: str = ""
    last_verified_at: str | None = None
    # Optional hardening fields. Missing values keep legacy behavior (not widened).
    allowed_schemes: list[str] = field(default_factory=lambda: ["http", "https"])
    # None = unrestricted ports (legacy). Explicit list restricts ports.
    allowed_ports: list[int] | None = None
    # When False, scope may pass for planning/dry-run but live execution is refused.
    live_execution_allowed: bool = True
    policy_version: str = "1"
    max_requests_per_assessment: int | None = None
    approval_evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizationRecord:
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        # Older registries without allowed_schemes keep http/https defaults.
        if "allowed_schemes" in data and data["allowed_schemes"] is None:
            known["allowed_schemes"] = ["http", "https"]
        if "live_execution_allowed" in data and data["live_execution_allowed"] is None:
            # Explicit null must fail closed rather than widen to True.
            known["live_execution_allowed"] = False
        return cls(**known)


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched_record: AuthorizationRecord | None = None
    policy_reference: str = ""
    decided_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy_version: str = SCOPE_POLICY_VERSION
    target: str = ""
    test_category: str = ""
    live_execution_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "policy_reference": self.policy_reference,
            "decided_at": self.decided_at,
            "policy_version": self.policy_version,
            "target": self.target,
            "test_category": self.test_category,
            "live_execution_allowed": self.live_execution_allowed,
            "matched_record": self.matched_record.to_dict() if self.matched_record else None,
        }
