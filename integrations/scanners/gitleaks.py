"""Gitleaks adapter — secret detection via optional local/container binary."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.execution import CommandRunner
from core.findings import FindingLifecycle, VerificationState, normalize_generic_finding, redact_secrets
from core.results import ExecutionResult
from integrations.base import AdapterRequest, SecurityAdapter


class GitleaksAdapter(SecurityAdapter):
    name = "gitleaks"
    version_pin = "8.21.2"
    requires_active_scope = False  # operates on local filesystem path only

    def __init__(self, *args, runner: CommandRunner | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.runner = runner or CommandRunner(max_log_bytes=self.config.max_log_bytes)

    def healthcheck(self) -> dict[str, Any]:
        path = self.runner.which("gitleaks")
        docker = self.runner.which("docker")
        version = None
        if path:
            res = self.runner.run(["gitleaks", "version"], timeout=20)
            version = (res.stdout or res.stderr or "").strip() if res.ok else None
        return {
            "tool": self.name,
            "healthy": bool(path) or bool(docker),
            "binary": path,
            "docker": docker,
            "version": version,
            "errors": [] if (path or docker) else ["gitleaks binary or docker required"],
        }

    def run(self, request: AdapterRequest) -> ExecutionResult:
        execution_id = str(uuid4())
        repo = Path(request.repo_path or request.target)
        if not repo.exists():
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error=f"Path not found: {repo}",
            )
        out_dir = Path(request.output_dir or self.config.reports_dir / f"gitleaks-{execution_id}")
        out_dir.mkdir(parents=True, exist_ok=True)
        report = out_dir / "gitleaks.json"
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
                "gitleaks",
                "detect",
                "--source",
                str(repo),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--no-git",
            ]
        elif health.get("docker"):
            cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{repo.resolve()}:/src:ro",
                f"zricethezav/gitleaks:v{self.version_pin}",
                "detect",
                "--source",
                "/src",
                "--report-format",
                "json",
                "--report-path",
                "/src/.gitleaks-report.json",
                "--no-git",
            ]
            # Prefer host report path when binary missing; docker write to mounted path needs rw.
            # Use a dedicated out mount instead.
            cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "-v",
                f"{repo.resolve()}:/src:ro",
                "-v",
                f"{out_dir.resolve()}:/out",
                f"zricethezav/gitleaks:v{self.version_pin}",
                "detect",
                "--source",
                "/src",
                "--report-format",
                "json",
                "--report-path",
                "/out/gitleaks.json",
                "--no-git",
            ]
        else:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="blocked",
                error="gitleaks not available",
                metadata={"health": health},
            )

        result = self.runner.run(cmd, timeout=request.timeout_seconds or 600)
        # gitleaks returns 1 when leaks found
        if result.returncode not in (0, 1) and not result.timed_out:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error=result.stderr or "gitleaks failed",
                artifacts={"log": result.stderr},
            )
        findings = self._parse(report, execution_id, str(repo))
        return ExecutionResult(
            tool=self.name,
            execution_id=execution_id,
            status="timed_out" if result.timed_out else "succeeded",
            findings=findings,
            artifacts={"report": str(report)},
            metadata={"returncode": result.returncode},
        )

    def _parse(self, report: Path, execution_id: str, asset: str) -> list:
        if not report.exists():
            return []
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        items = []
        for item in data if isinstance(data, list) else []:
            items.append(
                normalize_generic_finding(
                    title=str(item.get("Description") or item.get("RuleID") or "Secret detected"),
                    category="secret-detection",
                    source_tool=self.name,
                    source_tool_version=self.version_pin,
                    asset=asset,
                    severity="high",
                    evidence=redact_secrets(
                        {
                            "file": item.get("File"),
                            "rule": item.get("RuleID"),
                            "match": "[REDACTED]",
                        }
                    ),
                    remediation=["Rotate the credential and remove it from history where applicable."],
                    execution_id=execution_id,
                    verification_state=VerificationState.PARTIAL.value,
                    lifecycle=FindingLifecycle.EVIDENCE_COLLECTED.value,
                    confidence="medium",
                )
            )
        return items
