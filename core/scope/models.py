"""Authorization and scope record models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizationRecord:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched_record: AuthorizationRecord | None = None
    policy_reference: str = ""
    decided_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "policy_reference": self.policy_reference,
            "decided_at": self.decided_at,
            "matched_record": self.matched_record.to_dict() if self.matched_record else None,
        }
