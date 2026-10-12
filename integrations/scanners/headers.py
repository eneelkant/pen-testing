"""Passive security-headers checker (no payloads, HTTP GET only)."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from core.findings import FindingLifecycle, VerificationState, normalize_generic_finding
from core.results import ExecutionResult
from integrations.base import AdapterRequest, SecurityAdapter

RECOMMENDED_HEADERS = {
    "strict-transport-security": "medium",
    "content-security-policy": "medium",
    "x-content-type-options": "low",
    "x-frame-options": "low",
    "referrer-policy": "info",
    "permissions-policy": "info",
}


class HeadersAdapter(SecurityAdapter):
    name = "headers"
    version_pin = "0.1.0"
    requires_active_scope = True  # still requires authorization for remote targets

    def healthcheck(self) -> dict[str, Any]:
        return {"tool": self.name, "healthy": True, "mode": "passive-http-get"}

    def run(self, request: AdapterRequest) -> ExecutionResult:
        execution_id = str(uuid4())
        # Local fixture URLs (loopback) may skip scope when explicitly requested.
        is_loopback = any(
            h in request.target for h in ("127.0.0.1", "localhost", "[::1]")
        )
        if not (request.skip_scope_check and is_loopback):
            try:
                if self.scope_engine is not None and self.config.require_scope_for_active:
                    # Passive category is enough for header checks.
                    self.scope_engine.require(
                        request.target,
                        test_category=request.test_category or "passive",
                        require_non_production=not self.config.allow_production_active,
                    )
            except PermissionError as exc:
                return ExecutionResult(
                    tool=self.name,
                    execution_id=execution_id,
                    status="blocked",
                    error=str(exc),
                )

        if request.dry_run:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="skipped",
                metadata={"dry_run": True, "target": request.target},
            )

        try:
            req = Request(request.target, method="GET", headers={"User-Agent": "pen-testing-headers/0.1"})
            with urlopen(req, timeout=15) as resp:  # nosec B310 - target gated by scope engine
                headers = {k.lower(): v for k, v in resp.headers.items()}
                status_code = resp.status
        except HTTPError as exc:
            headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
            status_code = exc.code
        except (URLError, ValueError, TimeoutError) as exc:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error=f"Failed to fetch target: {exc}",
            )

        findings = []
        for header, severity in RECOMMENDED_HEADERS.items():
            if header not in headers:
                findings.append(
                    normalize_generic_finding(
                        title=f"Missing security header: {header}",
                        category="security-headers",
                        source_tool=self.name,
                        source_tool_version=self.version_pin,
                        asset=request.target,
                        severity=severity,
                        evidence={"status_code": status_code, "missing_header": header},
                        expected_behavior=f"Response includes {header}",
                        observed_behavior=f"{header} not present",
                        remediation=[f"Configure the origin to emit a strong {header} header."],
                        references=["https://owasp.org/www-project-secure-headers/"],
                        execution_id=execution_id,
                        verification_state=VerificationState.PARTIAL.value,
                        lifecycle=FindingLifecycle.EVIDENCE_COLLECTED.value,
                        confidence="medium",
                        impact="Missing browser security controls may increase client-side risk.",
                    )
                )

        return ExecutionResult(
            tool=self.name,
            execution_id=execution_id,
            status="succeeded",
            findings=findings,
            metadata={"status_code": status_code, "headers_seen": sorted(headers.keys())},
            artifacts={"headers_json": json.dumps(sorted(headers.keys()))},
        )
