"""Bound, short-lived assessment approvals for live MCP/CLI execution.

``confirm_authorized=true`` alone is not an authorization grant. Live runs must
present a single-use approval issued after scope and profile checks, bound to a
specific target, tool, category, mode, and plan fingerprint.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4
from urllib.parse import urlparse

DEFAULT_APPROVAL_TTL_SECONDS = 900
POLICY_VERSION = "assessment-approval-v1"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_approval_target(target: str) -> str:
    """Canonicalize a target for approval binding without resolving DNS."""
    text = (target or "").strip()
    if not text:
        raise ValueError("Target is empty")
    # Reject controls before urlparse: URL parsers may silently strip tabs/newlines,
    # which could make the approved string differ from the operator-supplied value.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise ValueError("Target contains control characters")
    if text[:7].lower() == "http://" or text[:8].lower() == "https://":
        parsed = urlparse(text)
        if parsed.username or parsed.password:
            raise ValueError("URL userinfo is not allowed in approval targets")
        if not parsed.hostname:
            raise ValueError("URL is missing a hostname")
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower().rstrip(".")
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Hostname is not a valid IDN") from exc
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{host}:{port}{path}{query}"
    # Local path / opaque targets: exact stripped form only.
    return text


def plan_fingerprint(
    *,
    tool: str,
    target: str,
    category: str,
    mode: str,
    profile_id: str,
    extra: dict[str, Any] | None = None,
) -> str:
    payload = {
        "tool": (tool or "").strip().lower(),
        "target": normalize_approval_target(target),
        "category": (category or "").strip().lower(),
        "mode": (mode or "").strip().lower(),
        "profile_id": (profile_id or "").strip().lower(),
        "extra": extra or {},
        "policy_version": POLICY_VERSION,
    }
    raw = repr(sorted(payload.items())).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass
class AssessmentApproval:
    approval_id: str
    target: str
    tool: str
    category: str
    mode: str
    profile_id: str
    plan_fingerprint: str
    policy_version: str = POLICY_VERSION
    issued_at: str = field(default_factory=lambda: _utcnow().isoformat())
    expires_at: str = ""
    consumed: bool = False
    single_use: bool = True
    scope_target_id: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ApprovalStore:
    """Process-local approval ledger. Not a multi-node authorization service."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[str, AssessmentApproval] = {}

    def reset(self) -> None:
        with self._lock:
            self._grants.clear()

    def issue(
        self,
        *,
        target: str,
        tool: str,
        category: str,
        mode: str,
        profile_id: str,
        plan_fingerprint: str,
        ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
        scope_target_id: str = "",
        reason: str = "Operator issued bound live-execution approval",
        now: datetime | None = None,
    ) -> AssessmentApproval:
        if ttl_seconds < 30 or ttl_seconds > 86_400:
            raise ValueError("ttl_seconds must be between 30 and 86400")
        moment = now or _utcnow()
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        normalized = normalize_approval_target(target)
        grant = AssessmentApproval(
            approval_id=str(uuid4()),
            target=normalized,
            tool=tool.strip().lower(),
            category=category.strip().lower(),
            mode=mode.strip().lower(),
            profile_id=(profile_id or "").strip().lower(),
            plan_fingerprint=plan_fingerprint,
            issued_at=moment.isoformat(),
            expires_at=(moment + timedelta(seconds=ttl_seconds)).isoformat(),
            scope_target_id=scope_target_id,
            reason=reason,
        )
        with self._lock:
            self._grants[grant.approval_id] = grant
        return grant

    def peek(self, approval_id: str) -> AssessmentApproval | None:
        with self._lock:
            return self._grants.get(approval_id)

    def consume(
        self,
        approval_id: str,
        *,
        target: str,
        tool: str,
        category: str,
        mode: str,
        profile_id: str,
        plan_fingerprint: str,
        now: datetime | None = None,
    ) -> AssessmentApproval:
        if not approval_id or not str(approval_id).strip():
            raise PermissionError("Live execution requires a bound approval_id")
        moment = now or _utcnow()
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        normalized = normalize_approval_target(target)
        with self._lock:
            grant = self._grants.get(approval_id.strip())
            if grant is None:
                raise PermissionError("Approval not found or already invalid")
            if grant.consumed and grant.single_use:
                raise PermissionError("Approval has already been consumed")
            expires = datetime.fromisoformat(grant.expires_at)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if moment > expires:
                raise PermissionError("Approval has expired")
            if grant.policy_version != POLICY_VERSION:
                raise PermissionError("Approval policy version mismatch")
            if grant.target != normalized:
                raise PermissionError("Approval target does not match the requested target")
            if grant.tool != tool.strip().lower():
                raise PermissionError("Approval tool does not match the requested tool")
            if grant.category != category.strip().lower():
                raise PermissionError("Approval category does not match the request")
            if grant.mode != mode.strip().lower():
                raise PermissionError("Approval mode does not match the request")
            if grant.profile_id != (profile_id or "").strip().lower():
                raise PermissionError("Approval profile does not match the request")
            if grant.plan_fingerprint != plan_fingerprint:
                raise PermissionError("Approval plan fingerprint does not match the request")
            grant.consumed = True
            return grant


_STORE = ApprovalStore()


def get_approval_store() -> ApprovalStore:
    return _STORE


def reset_approval_store() -> None:
    _STORE.reset()
