"""Bound, expiring execution approvals for live assessments.

A client-supplied ``confirm_authorized=true`` flag is not proof of authorization.
Approvals are issued only after a successful scope decision and are bound to the
exact target, tool, category, optional assessment profile, execution plan hash,
and a fingerprint of the matched authorization policy. They expire, are single-use
for live execution, and fail closed on mismatch or policy change.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from core.findings.redaction import redact_secrets
from core.scope.models import AuthorizationRecord, ScopeDecision


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def policy_fingerprint(record: AuthorizationRecord | None, *, registry_digest: str = "") -> str:
    """Stable fingerprint of the authorizing policy used at approval time."""
    payload = {
        "registry_digest": registry_digest,
        "record": record.to_dict() if record else None,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def execution_plan_hash(
    *,
    tool: str,
    target: str,
    category: str,
    mode: str = "standard",
    profile_id: str | None = None,
    capabilities: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    payload = {
        "tool": tool.lower().strip(),
        "target": target.strip(),
        "category": category.lower().strip(),
        "mode": mode.lower().strip(),
        "profile_id": profile_id,
        "capabilities": sorted(capabilities or []),
        "extra": extra or {},
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def registry_content_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class ExecutionApproval:
    approval_id: str
    target: str
    tool: str
    category: str
    profile_id: str | None
    execution_plan_hash: str
    policy_fingerprint: str
    issued_at: str
    expires_at: str
    used: bool = False
    status: str = "active"  # active | consumed | expired | revoked
    reason: str = ""
    audit: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_secrets(asdict(self))

    def is_expired(self, *, now: datetime | None = None) -> bool:
        moment = now or _utcnow()
        return moment > _parse_dt(self.expires_at)


class ApprovalStore:
    """Process-local approval ledger. Fail closed when validation cannot complete."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[str, ExecutionApproval] = {}

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def issue(
        self,
        *,
        target: str,
        tool: str,
        category: str,
        decision: ScopeDecision,
        plan_hash: str,
        profile_id: str | None = None,
        registry_digest: str = "",
        ttl_seconds: int = 900,
        now: datetime | None = None,
        audit: dict[str, Any] | None = None,
    ) -> ExecutionApproval:
        if ttl_seconds < 60 or ttl_seconds > 86_400:
            raise PermissionError("Approval TTL must be between 60 and 86400 seconds")
        if not decision.allowed:
            raise PermissionError(f"Cannot issue approval: {decision.reason}")
        if not target.strip() or not tool.strip() or not category.strip() or not plan_hash.strip():
            raise PermissionError("Approval requires target, tool, category, and execution plan hash")

        moment = now or _utcnow()
        approval = ExecutionApproval(
            approval_id=str(uuid4()),
            target=target.strip(),
            tool=tool.lower().strip(),
            category=category.lower().strip(),
            profile_id=profile_id,
            execution_plan_hash=plan_hash.strip(),
            policy_fingerprint=policy_fingerprint(decision.matched_record, registry_digest=registry_digest),
            issued_at=moment.isoformat(),
            expires_at=(moment + timedelta(seconds=ttl_seconds)).isoformat(),
            reason=decision.reason,
            audit=redact_secrets(
                {
                    "policy_reference": decision.policy_reference,
                    "decided_at": decision.decided_at,
                    **(audit or {}),
                }
            ),
        )
        with self._lock:
            self._items[approval.approval_id] = approval
        return approval

    def get(self, approval_id: str) -> ExecutionApproval | None:
        with self._lock:
            return self._items.get(approval_id)

    def revoke(self, approval_id: str, *, reason: str = "revoked") -> ExecutionApproval:
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                raise PermissionError("Approval not found")
            item.status = "revoked"
            item.reason = reason
            return item

    def consume(
        self,
        approval_id: str,
        *,
        target: str,
        tool: str,
        category: str,
        plan_hash: str,
        policy_fingerprint_now: str,
        profile_id: str | None = None,
        now: datetime | None = None,
    ) -> ExecutionApproval:
        """Validate binding and mark the approval consumed. Fail closed on any mismatch."""
        moment = now or _utcnow()
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                raise PermissionError("Approval not found")
            if item.status == "revoked":
                raise PermissionError("Approval has been revoked")
            if item.status == "consumed" or item.used:
                raise PermissionError("Approval has already been consumed")
            if item.is_expired(now=moment):
                item.status = "expired"
                raise PermissionError("Approval has expired")
            if item.target != target.strip():
                raise PermissionError("Approval target mismatch")
            if item.tool != tool.lower().strip():
                raise PermissionError("Approval tool mismatch")
            if item.category != category.lower().strip():
                raise PermissionError("Approval category mismatch")
            if (item.profile_id or None) != (profile_id or None):
                raise PermissionError("Approval profile mismatch")
            if item.execution_plan_hash != plan_hash.strip():
                raise PermissionError("Approval execution plan mismatch")
            if item.policy_fingerprint != policy_fingerprint_now:
                raise PermissionError("Authorization policy changed since approval was issued")
            item.used = True
            item.status = "consumed"
            return item


_STORE = ApprovalStore()


def get_approval_store() -> ApprovalStore:
    return _STORE


def reset_approval_store() -> None:
    """Test helper."""
    _STORE.clear()
