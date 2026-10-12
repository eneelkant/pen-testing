"""Trivy adapter — dependency/filesystem vulnerability scanning (optional binary/container)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.execution import CommandRunner
from core.findings import FindingLifecycle, VerificationState, normalize_generic_finding, redact_secrets
from core.paths import confine_path
from core.results import ExecutionResult
from integrations.base import AdapterRequest, SecurityAdapter


class TrivyAdapter(SecurityAdapter):
    name = "trivy"
    version_pin = "0.58.1"
    requires_active_scope = False

    def __init__(self, *args, runner: CommandRunner | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.runner = runner or CommandRunner(max_log_bytes=self.config.max_log_bytes)

    def healthcheck(self) -> dict[str, Any]:
        path = self.runner.which("trivy")
        docker = self.runner.which("docker")
        version = None
        if path:
            res = self.runner.run(["trivy", "--version"], timeout=20)
            version = (res.stdout or "").splitlines()[0] if res.ok else None
        return {
            "tool": self.name,
            "healthy": bool(path) or bool(docker),
            "binary": path,
            "docker": docker,
            "version": version,
            "errors": [] if (path or docker) else ["trivy binary or docker required"],
        }

    def run(self, request: AdapterRequest) -> ExecutionResult:
        execution_id = str(uuid4())
        roots = [Path(self.config.work_dir), Path(self.config.reports_dir), Path.cwd()]
        try:
            target = confine_path(request.repo_path or request.target, roots)
        except PermissionError as exc:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="blocked",
                error=str(exc),
            )
        if not target.exists():
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error=f"Path not found: {target}",
            )
        out_dir = Path(request.output_dir or self.config.reports_dir / f"trivy-{execution_id}")
        out_dir.mkdir(parents=True, exist_ok=True)
        report = out_dir / "trivy.json"
        health = self.healthcheck()
        if request.dry_run:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="skipped",
                metadata={"dry_run": True, "health": health},
            )
        if health.get("binary"):
            cmd = [
                "trivy",
                "fs",
                "--format",
                "json",
                "--output",
                str(report),
                str(target),
            ]
        elif health.get("docker"):
            # Prefer offline/cache-friendly isolation. Network disabled to match Gitleaks.
            # Operators needing DB refresh should run `trivy image --download-db-only` on the host.
            cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{target.resolve()}:/src:ro",
                "-v",
                f"{out_dir.resolve()}:/out",
                f"aquasec/trivy:{self.version_pin}",
                "fs",
                "--skip-db-update",
                "--format",
                "json",
                "--output",
                "/out/trivy.json",
                "/src",
            ]
        else:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="blocked",
                error="trivy not available",
                metadata={"health": health},
            )

        result = self.runner.run(cmd, timeout=request.timeout_seconds or 900)
        if not result.ok:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="timed_out" if result.timed_out else "failed",
                error=result.stderr or "trivy failed",
            )
        findings = self._parse(report, execution_id, str(target))
        return ExecutionResult(
            tool=self.name,
            execution_id=execution_id,
            status="succeeded",
            findings=findings,
            artifacts={"report": str(report)},
        )

    def _parse(self, report: Path, execution_id: str, asset: str) -> list:
        if not report.exists():
            return []
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        items = []
        results = data.get("Results", []) if isinstance(data, dict) else []
        for block in results:
            for vuln in block.get("Vulnerabilities") or []:
                items.append(
                    normalize_generic_finding(
                        title=str(vuln.get("Title") or vuln.get("VulnerabilityID") or "Dependency vulnerability"),
                        category="dependency",
                        source_tool=self.name,
                        source_tool_version=self.version_pin,
                        asset=asset,
                        severity=str(vuln.get("Severity") or "info").lower(),
                        evidence=redact_secrets(
                            {
                                "id": vuln.get("VulnerabilityID"),
                                "pkg": vuln.get("PkgName"),
                                "installed": vuln.get("InstalledVersion"),
                                "fixed": vuln.get("FixedVersion"),
                            }
                        ),
                        references=[str(u) for u in vuln.get("References") or []],
                        remediation=["Upgrade the affected package to a fixed version when available."],
                        execution_id=execution_id,
                        verification_state=VerificationState.UNVERIFIED.value,
                        lifecycle=FindingLifecycle.CANDIDATE.value,
                        confidence="medium",
                    )
                )
        return items
