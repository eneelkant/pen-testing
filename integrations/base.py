"""Adapter interface for security testing tools."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from core.config import PlatformConfig
from core.isolation import assert_live_destination_allowed, load_isolation_policy
from core.results import ExecutionResult
from core.scope import ScopeEngine
from core.scope.rate_limit import enforce_rate_limit, enforce_unscoped_rate_limit


@dataclass
class AdapterRequest:
    target: str
    test_category: str = "active"
    repo_path: str | None = None
    mode: str = "standard"
    timeout_seconds: int | None = None
    output_dir: str | None = None
    workspace: str | None = None
    config_path: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False
    # Skips authorization registry only. Does NOT skip launch-time egress / DNS policy.
    # Callers must gate this flag (CLI requires PEN_ALLOW_SKIP_SCOPE=1).
    skip_scope_check: bool = False


class SecurityAdapter(ABC):
    name: str
    version_pin: str
    requires_active_scope: bool = True
    # Remote HTTP-targeting tools that must pass resolve-time egress policy when live.
    requires_egress_policy: bool = False

    def __init__(self, config: PlatformConfig, scope_engine: ScopeEngine | None = None):
        self.config = config
        self.scope_engine = scope_engine

    @abstractmethod
    def healthcheck(self) -> dict[str, Any]:
        """Return capability / dependency status without scanning."""

    @abstractmethod
    def run(self, request: AdapterRequest) -> ExecutionResult:
        """Execute the tool (or dry-run) and return normalized results."""

    def preflight(self, request: AdapterRequest) -> None:
        if not self.requires_active_scope:
            return
        if request.skip_scope_check:
            # Callers must gate this flag (CLI requires PEN_ALLOW_SKIP_SCOPE=1).
            # Egress checks stay in egress_preflight. This limit is the rate control
            # that still applies when the registry is skipped.
            if not request.dry_run:
                enforce_unscoped_rate_limit()
            return
        isolation = load_isolation_policy()
        if not self.config.require_scope_for_active:
            # Dual gate: PEN_REQUIRE_SCOPE=false alone is insufficient.
            if not isolation.allow_scope_disable:
                raise PermissionError(
                    "PEN_REQUIRE_SCOPE is disabled but PEN_ALLOW_SCOPE_DISABLE is not set; "
                    "refusing to weaken authorization (operator dual-gate)."
                )
            # Disabling the registry must not disable live rate control.
            if not request.dry_run:
                enforce_unscoped_rate_limit()
            return
        if self.scope_engine is None:
            raise PermissionError("Scope engine is required for active testing")
        decision = self.scope_engine.require(
            request.target,
            test_category=request.test_category,
            require_non_production=not self.config.allow_production_active,
            for_live_execution=not request.dry_run,
        )
        if not request.dry_run:
            enforce_rate_limit(decision)

    def egress_preflight(self, request: AdapterRequest) -> None:
        """Launch-time destination gate for live remote engines (not in-engine containment).

        Independent of ``skip_scope_check``: skipping the authorization registry must not
        disable DNS / non-public destination evaluation for Shannon/Briar launches.
        """
        if not self.requires_egress_policy:
            return
        if request.dry_run:
            return
        if not (request.target or "").strip():
            raise PermissionError("Target is required for egress policy evaluation")
        # When scope was skipped, still evaluate resolve-time policy without re-applying
        # the registry (scope may be None or intentionally bypassed for fixtures).
        scope_for_egress = None if request.skip_scope_check else self.scope_engine
        assert_live_destination_allowed(
            request.target,
            scope_engine=scope_for_egress,
            test_category=request.test_category,
            dry_run=False,
        )
