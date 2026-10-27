"""Assessment profiles: declarative limits for authorized research workflows.

Profiles never authorize a target by themselves. Scope registry + bound approval
remain mandatory for live remote execution. Profiles default to fail-closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

TRANSACTION_CAPABILITIES = frozenset(
    {
        "place_order",
        "modify_order",
        "cancel_order",
        "exit_position",
        "fund_transfer",
        "withdrawal",
        "trading_transaction",
        "transaction",
    }
)

PROHIBITED_DEFAULT = frozenset(
    {
        "credential_stuffing",
        "password_guessing",
        "otp_bruteforce",
        "otp_bruteforcing",
        "mfa_bypass",
        "dos",
        "ddos",
        "high_volume",
        "data_destruction",
        "account_enumeration",
        "customer_enumeration",
        *TRANSACTION_CAPABILITIES,
    }
)


@dataclass(frozen=True)
class AssessmentProfile:
    profile_id: str
    display_name: str
    live_execution_enabled: bool = False
    require_bound_approval: bool = True
    require_scope_check: bool = True
    dry_run_default: bool = True
    allowed_categories: tuple[str, ...] = ("passive",)
    allowed_tools: tuple[str, ...] = ("headers",)
    allowed_capabilities: tuple[str, ...] = ()
    prohibited_capabilities: tuple[str, ...] = tuple(sorted(PROHIBITED_DEFAULT))
    synthetic_targets_only: bool = True
    allowed_synthetic_hosts: tuple[str, ...] = ()
    max_concurrency: int = 1
    timeout_seconds: int = 120
    rate_limit_rps: float = 1.0
    redact_sensitive_output: bool = True
    notes: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "display_name": self.display_name,
            "live_execution_enabled": self.live_execution_enabled,
            "require_bound_approval": self.require_bound_approval,
            "require_scope_check": self.require_scope_check,
            "dry_run_default": self.dry_run_default,
            "allowed_categories": list(self.allowed_categories),
            "allowed_tools": list(self.allowed_tools),
            "allowed_capabilities": list(self.allowed_capabilities),
            "prohibited_capabilities": list(self.prohibited_capabilities),
            "synthetic_targets_only": self.synthetic_targets_only,
            "allowed_synthetic_hosts": list(self.allowed_synthetic_hosts),
            "max_concurrency": self.max_concurrency,
            "timeout_seconds": self.timeout_seconds,
            "rate_limit_rps": self.rate_limit_rps,
            "redact_sensitive_output": self.redact_sensitive_output,
            "notes": self.notes,
        }


def _as_tuple(value: Any, *, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, (list, tuple)):
        raise ValueError("Expected a list of strings")
    out = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("List entries must be non-empty strings")
        out.append(item.strip())
    return tuple(out)


def load_assessment_profile(path: str | Path) -> AssessmentProfile:
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"Assessment profile not found: {cfg_path}")
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("Assessment profile root must be a mapping")

    profile_id = str(data.get("profile_id") or data.get("id") or "").strip()
    display_name = str(data.get("display_name") or data.get("name") or profile_id).strip()
    if not profile_id:
        raise ValueError("Assessment profile requires profile_id")

    prohibited = _as_tuple(data.get("prohibited_capabilities"), default=tuple(sorted(PROHIBITED_DEFAULT)))
    # Fail closed: transaction capabilities cannot be removed from prohibited set via omission.
    prohibited_set = set(prohibited) | set(TRANSACTION_CAPABILITIES) | {
        "credential_stuffing",
        "password_guessing",
        "otp_bruteforce",
        "dos",
        "high_volume",
        "data_destruction",
    }

    live = bool(data.get("live_execution_enabled", False))
    # Hard safety: profiles marked synthetic_targets_only cannot enable live by YAML alone
    # without an explicit allow_live_override that still leaves live default false unless set.
    synthetic_only = bool(data.get("synthetic_targets_only", True))
    if synthetic_only and live and not bool(data.get("allow_live_override", False)):
        live = False

    return AssessmentProfile(
        profile_id=profile_id,
        display_name=display_name,
        live_execution_enabled=live,
        require_bound_approval=bool(data.get("require_bound_approval", True)),
        require_scope_check=bool(data.get("require_scope_check", True)),
        dry_run_default=bool(data.get("dry_run_default", True)),
        allowed_categories=_as_tuple(data.get("allowed_categories"), default=("passive",)),
        allowed_tools=_as_tuple(data.get("allowed_tools"), default=("headers",)),
        allowed_capabilities=_as_tuple(data.get("allowed_capabilities"), default=()),
        prohibited_capabilities=tuple(sorted(prohibited_set)),
        synthetic_targets_only=synthetic_only,
        allowed_synthetic_hosts=_as_tuple(data.get("allowed_synthetic_hosts"), default=()),
        max_concurrency=max(1, int(data.get("max_concurrency", 1))),
        timeout_seconds=max(1, int(data.get("timeout_seconds", 120))),
        rate_limit_rps=float(data.get("rate_limit_rps", 1.0)),
        redact_sensitive_output=bool(data.get("redact_sensitive_output", True)),
        notes=str(data.get("notes") or ""),
        raw=data,
    )


def profile_blocks_live_execution(profile: AssessmentProfile) -> tuple[bool, str]:
    if not profile.live_execution_enabled:
        return True, (
            f"Assessment profile '{profile.profile_id}' disables live execution by default. "
            "Human authorization and an explicit profile change are required before any live run."
        )
    return False, "live permitted by profile flag (scope and approval still required)"


def profile_allows_capability(profile: AssessmentProfile, capability: str) -> tuple[bool, str]:
    cap = capability.lower().strip()
    if not cap:
        return False, "Capability is empty"
    if cap in {p.lower() for p in profile.prohibited_capabilities}:
        return False, f"Capability '{cap}' is prohibited by profile '{profile.profile_id}'"
    if cap in TRANSACTION_CAPABILITIES:
        return False, f"Transaction-capable operation '{cap}' is never allowed in assessment profiles"
    allowed = {a.lower() for a in profile.allowed_capabilities}
    if allowed and cap not in allowed:
        return False, f"Capability '{cap}' is not in the profile allowlist"
    return True, "ok"


def assert_profile_request_allowed(
    profile: AssessmentProfile,
    *,
    tool: str,
    category: str,
    target_host: str | None,
    dry_run: bool,
) -> None:
    """Raise PermissionError when the request violates the loaded profile."""
    if tool.lower().strip() not in {t.lower() for t in profile.allowed_tools}:
        raise PermissionError(f"Tool '{tool}' is not allowed by profile '{profile.profile_id}'")
    if category.lower().strip() not in {c.lower() for c in profile.allowed_categories}:
        raise PermissionError(
            f"Category '{category}' is not allowed by profile '{profile.profile_id}'"
        )
    blocked, reason = profile_blocks_live_execution(profile)
    if not dry_run and blocked:
        raise PermissionError(reason)
    if profile.synthetic_targets_only and target_host:
        allowed_hosts = {h.lower() for h in profile.allowed_synthetic_hosts}
        # Loopback fixtures remain acceptable for local dry-run validation.
        loopback = target_host.lower() in {"127.0.0.1", "localhost", "::1"}
        if allowed_hosts and target_host.lower() not in allowed_hosts and not (
            dry_run and loopback
        ):
            if not loopback:
                raise PermissionError(
                    f"Host '{target_host}' is not an allowed synthetic host for profile "
                    f"'{profile.profile_id}'"
                )
