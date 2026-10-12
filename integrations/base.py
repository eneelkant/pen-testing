"""Adapter interface for security testing tools."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from core.config import PlatformConfig
from core.isolation import assert_live_destination_allowed, load_isolation_policy
from core.results import ExecutionResult
from core.scope import ScopeEngine


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
    skip_scope_check: bool = False  # only for local fixtures / unit tests


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
            return
        isolation = load_isolation_policy()
        if not self.config.require_scope_for_active:
            # Dual gate: PEN_REQUIRE_SCOPE=false alone is insufficient.
            if not isolation.allow_scope_disable:
                raise PermissionError(
                    "PEN_REQUIRE_SCOPE is disabled but PEN_ALLOW_SCOPE_DISABLE is not set; "
                    "refusing to weaken authorization (operator dual-gate)."
                )
            return
        if self.scope_engine is None:
            raise PermissionError("Scope engine is required for active testing")
        self.scope_engine.require(
            request.target,
            test_category=request.test_category,
            require_non_production=not self.config.allow_production_active,
        )

    def egress_preflight(self, request: AdapterRequest) -> None:
        """Launch-time destination gate for live remote engines (not in-engine containment)."""
        if not self.requires_egress_policy:
            return
        if request.dry_run or request.skip_scope_check:
            return
        if not (request.target or "").strip():
            raise PermissionError("Target is required for egress policy evaluation")
        assert_live_destination_allowed(
            request.target,
            scope_engine=self.scope_engine,
            test_category=request.test_category,
            dry_run=False,
        )
