"""Local-only MobSFScan adapter for mobile application source code."""

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

EXPECTED_VERSION = "1.0.1"


class MobSFScanAdapter(SecurityAdapter):
    name = "mobsfscan"
    version_pin = EXPECTED_VERSION
    requires_active_scope = False

    def __init__(self, *args, runner: CommandRunner | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.runner = runner or CommandRunner(max_log_bytes=self.config.max_log_bytes)

    def healthcheck(self) -> dict[str, Any]:
        binary = self.runner.which("mobsfscan")
        try:
            installed_version = version("mobsfscan")
        except PackageNotFoundError:
            installed_version = None
        healthy = bool(binary) and installed_version == self.version_pin
        errors = []
        if not binary:
            errors.append("mobsfscan executable not found; install the optional mobsfscan extra")
        if installed_version != self.version_pin:
            errors.append(
                f"mobsfscan Python distribution must be {self.version_pin}; found {installed_version or 'not installed'}"
            )
        return {
            "tool": self.name,
            "healthy": healthy,
            "binary": binary,
            "version": installed_version,
            "expected_version": self.version_pin,
            "network_access": "local source analysis; telemetry disabled for child process",
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
                error="MobSFScan target must be an existing local source file or directory",
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
                error="Required pinned MobSFScan executable is unavailable",
                metadata={"health": health},
            )

        try:
            output_dir = confine_path(
                request.output_dir or Path(self.config.reports_dir) / f"mobsfscan-{execution_id}",
                [Path(self.config.reports_dir), Path(self.config.work_dir)],
            )
            output_dir.mkdir(parents=True, exist_ok=True)
            if output_dir.is_symlink():
                raise PermissionError(f"Refusing symlink output directory: {output_dir}")
        except PermissionError as exc:
            return ExecutionResult(
                tool=self.name, execution_id=execution_id, status="blocked", error=str(exc)
            )

        report = output_dir / "mobsfscan.json"
        command = [
            health["binary"],
            "--json",
            "--no-fail",
            "-o",
            str(report),
            str(target),
        ]
        result = self.runner.run(
            command,
            timeout=request.timeout_seconds or 600,
            env={"SEMGREP_SEND_METRICS": "off"},
        )
        if result.timed_out:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="timed_out",
                error="MobSFScan timed out",
                metadata={"duration_seconds": result.duration_seconds},
            )
        if result.returncode != 0:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error=result.stderr or f"MobSFScan exited with code {result.returncode}",
                metadata={"returncode": result.returncode},
            )
        if report.is_symlink() or not report.is_file():
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="MobSFScan did not produce a regular JSON report",
            )
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="MobSFScan did not produce valid JSON",
            )
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, dict):
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="MobSFScan JSON is missing the results object",
            )

        findings = []
        for rule_id, rule_data in results.items():
            if not isinstance(rule_data, dict):
                continue
            metadata = rule_data.get("metadata") if isinstance(rule_data.get("metadata"), dict) else {}
            files = rule_data.get("files") or []
            if not isinstance(files, list):
                continue
            raw_severity = str(metadata.get("severity") or "WARNING").upper()
            severity = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "ERROR": "high",
                "MEDIUM": "medium",
                "WARNING": "medium",
                "LOW": "low",
                "INFO": "info",
            }.get(raw_severity, "medium")
            for match in files:
                if not isinstance(match, dict):
                    continue
                raw_lines = match.get("match_lines") or []
                lines = []
                if isinstance(raw_lines, (list, tuple)):
                    for line in raw_lines:
                        try:
                            lines.append(int(line))
                        except (TypeError, ValueError):
                            continue
                reference = metadata.get("reference")
                references = []
                if isinstance(reference, str) and reference.startswith(("https://", "http://")):
                    references.append(reference)
                owasp = metadata.get("owasp-mobile")
                masvs = metadata.get("masvs")
                evidence = {
                    "rule_id": str(rule_id),
                    "file_path": match.get("file_path"),
                    "line_numbers": sorted(set(lines)),
                    "owasp_mobile": owasp,
                    "masvs": masvs,
                }
                description = metadata.get("description")
                findings.append(
                    normalize_generic_finding(
                        title=str(rule_id).replace("_", " ").strip() or "Mobile source-code issue",
                        category="mobile-source-analysis",
                        source_tool=self.name,
                        source_tool_version=self.version_pin,
                        asset=str(target),
                        severity=severity,
                        evidence=evidence,
                        references=references,
                        remediation=[str(description)] if isinstance(description, str) and description else [
                            "Review the mobile security rule and remediate the vulnerable source pattern."
                        ],
                        execution_id=execution_id,
                        verification_state=VerificationState.UNVERIFIED.value,
                        lifecycle=FindingLifecycle.CANDIDATE.value,
                        confidence="medium",
                    )
                )

        # Replace source snippets from the upstream raw report with a sanitized normalized summary.
        summary = {
            "tool": self.name,
            "version": self.version_pin,
            "finding_count": len(findings),
            "findings": [finding.to_dict() for finding in findings],
        }
        try:
            safe_write_text(report, json.dumps(summary, indent=2) + "\n")
        except (OSError, PermissionError) as exc:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error=f"Could not safely write sanitized MobSFScan report: {exc}",
                findings=findings,
            )

        return ExecutionResult(
            tool=self.name,
            execution_id=execution_id,
            status="succeeded",
            findings=findings,
            artifacts={"report": str(report)},
            metadata={"target": str(target), "version": self.version_pin},
        )
