"""Local-only Checkov IaC/configuration adapter.

This adapter requires the explicitly installed, version-pinned Checkov CLI.
It runs with platform downloads disabled and never scans remote targets.
"""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.execution import CommandRunner
from core.findings import FindingLifecycle, VerificationState, normalize_generic_finding
from core.paths import confine_path, safe_write_text
from core.results import ExecutionResult
from integrations.base import AdapterRequest, SecurityAdapter

EXPECTED_VERSION = "3.3.29"


class CheckovAdapter(SecurityAdapter):
    name = "checkov"
    version_pin = EXPECTED_VERSION
    requires_active_scope = False

    def __init__(self, *args, runner: CommandRunner | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.runner = runner or CommandRunner(max_log_bytes=self.config.max_log_bytes)

    def healthcheck(self) -> dict[str, Any]:
        binary = self.runner.which("checkov")
        try:
            installed_version = version("checkov")
        except PackageNotFoundError:
            installed_version = None
        healthy = bool(binary) and installed_version == self.version_pin
        errors = []
        if not binary:
            errors.append("checkov executable not found; install the optional checkov extra")
        if installed_version != self.version_pin:
            errors.append(
                f"checkov Python distribution must be {self.version_pin}; found {installed_version or 'not installed'}"
            )
        return {
            "tool": self.name,
            "healthy": healthy,
            "binary": binary,
            "version": installed_version,
            "expected_version": self.version_pin,
            "network_access": "disabled for Checkov platform downloads with --skip-download",
            "errors": errors,
        }

    def run(self, request: AdapterRequest) -> ExecutionResult:
        execution_id = str(uuid4())
        roots = [Path(self.config.work_dir), Path(self.config.reports_dir), Path.cwd()]
        try:
            target = confine_path(request.repo_path or request.target, roots)
        except PermissionError as exc:
            return ExecutionResult(
                tool=self.name, execution_id=execution_id, status="blocked", error=str(exc)
            )
        if not target.exists() or not (target.is_file() or target.is_dir()):
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="Checkov target must be an existing local file or directory",
            )

        health = self.healthcheck()
        if request.dry_run:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="skipped",
                metadata={"dry_run": True, "health": health, "target": str(target)},
            )
        if not health["healthy"]:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="blocked",
                error="Required pinned Checkov executable is unavailable",
                metadata={"health": health},
            )

        try:
            output_dir = confine_path(
                request.output_dir or Path(self.config.reports_dir) / f"checkov-{execution_id}",
                [Path(self.config.reports_dir), Path(self.config.work_dir)],
            )
            output_dir.mkdir(parents=True, exist_ok=True)
            if output_dir.is_symlink():
                raise PermissionError(f"Refusing symlink output directory: {output_dir}")
        except PermissionError as exc:
            return ExecutionResult(
                tool=self.name, execution_id=execution_id, status="blocked", error=str(exc)
            )

        report_candidates = [
            output_dir / "results_json.json",
            output_dir / "results.json",
            output_dir / "checkov.json",
        ]
        command = [
            health["binary"],
            "-d" if target.is_dir() else "-f",
            str(target),
            "-o",
            "json",
            "--output-file-path",
            str(output_dir),
            "--skip-download",
            "--skip-results-upload",
            "--download-external-modules",
            "false",
        ]
        result = self.runner.run(
            command,
            timeout=request.timeout_seconds or 900,
            env={
                "CHECKOV_ENABLE_TELEMETRY": "false",
                "BC_API_KEY": "",
                "PRISMA_API_URL": "",
            },
        )
        if result.timed_out:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="timed_out",
                error="Checkov timed out",
                metadata={"duration_seconds": result.duration_seconds},
            )

        data = None
        report_path = None
        for candidate in report_candidates:
            if candidate.is_file() and not candidate.is_symlink():
                try:
                    data = json.loads(candidate.read_text(encoding="utf-8"))
                    report_path = candidate
                    break
                except (OSError, json.JSONDecodeError):
                    continue
        if data is None and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                data = None
        if not isinstance(data, dict) or not isinstance(data.get("results"), dict):
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="Checkov did not produce a valid JSON results document",
                metadata={"returncode": result.returncode},
            )

        report_results = data["results"]
        failed_checks = report_results.get("failed_checks")
        if not isinstance(failed_checks, list):
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="Checkov JSON is missing the failed_checks array",
            )
        parsing_errors = report_results.get("parsing_errors") or []
        if not isinstance(parsing_errors, list):
            parsing_errors = ["invalid parsing_errors field"]

        findings = []
        for item in failed_checks:
            if not isinstance(item, dict):
                continue
            raw_severity = str(item.get("severity") or "medium").upper()
            severity = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFO": "info",
            }.get(raw_severity, "medium")
            lines = []
            code_block = item.get("code_block")
            if isinstance(code_block, list):
                for block_line in code_block:
                    if isinstance(block_line, (list, tuple)) and block_line:
                        try:
                            lines.append(int(block_line[0]))
                        except (TypeError, ValueError):
                            continue
            guideline = item.get("guideline")
            remediation = [str(guideline)] if isinstance(guideline, str) and guideline else [
                "Review the Checkov control and apply the documented configuration remediation."
            ]
            findings.append(
                normalize_generic_finding(
                    title=str(item.get("check_name") or item.get("check_id") or "IaC configuration issue"),
                    category="infrastructure-configuration",
                    source_tool=self.name,
                    source_tool_version=self.version_pin,
                    asset=str(target),
                    severity=severity,
                    evidence={
                        "check_id": item.get("check_id"),
                        "resource": item.get("resource"),
                        "file_path": item.get("file_path"),
                        "line_numbers": sorted(set(lines)),
                        "check_type": item.get("check_type"),
                    },
                    references=[guideline] if isinstance(guideline, str) and guideline.startswith("https://") else [],
                    remediation=remediation,
                    execution_id=execution_id,
                    verification_state=VerificationState.UNVERIFIED.value,
                    lifecycle=FindingLifecycle.CANDIDATE.value,
                    confidence="medium",
                )
            )

        summary = {
            "tool": self.name,
            "version": self.version_pin,
            "finding_count": len(findings),
            "parsing_error_count": len(parsing_errors),
            "findings": [finding.to_dict() for finding in findings],
        }
        sanitized_report = report_path or output_dir / "checkov-normalized.json"
        try:
            safe_write_text(sanitized_report, json.dumps(summary, indent=2) + "\n")
        except (OSError, PermissionError) as exc:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error=f"Could not safely write sanitized Checkov report: {exc}",
                findings=findings,
            )

        incomplete = bool(parsing_errors)
        return ExecutionResult(
            tool=self.name,
            execution_id=execution_id,
            status="failed" if incomplete or result.returncode not in (0, 1) else "succeeded",
            error=f"Checkov reported {len(parsing_errors)} parsing error(s)" if incomplete else None,
            findings=findings,
            artifacts={"report": str(sanitized_report)},
            metadata={
                "returncode": result.returncode,
                "parsing_error_count": len(parsing_errors),
                "target": str(target),
                "version": self.version_pin,
            },
        )
