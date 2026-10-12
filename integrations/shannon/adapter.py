"""Shannon adapter — invokes upstream CLI via npx; does not vendor Shannon source."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.execution import CommandRunner
from core.findings import FindingLifecycle, VerificationState, normalize_generic_finding, redact_secrets
from core.logging import audit_event
from core.results import ExecutionResult
from integrations.base import AdapterRequest, SecurityAdapter


class ShannonAdapter(SecurityAdapter):
    name = "shannon"
    version_pin = "3.4.0"
    requires_active_scope = True
    requires_egress_policy = True

    def __init__(self, *args, runner: CommandRunner | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.runner = runner or CommandRunner(max_log_bytes=self.config.max_log_bytes)
        self.package = self.config.shannon_package

    def healthcheck(self) -> dict[str, Any]:
        node = self.runner.which("node")
        npx = self.runner.which("npx")
        docker = self.runner.which("docker")
        status: dict[str, Any] = {
            "tool": self.name,
            "pinned_package": self.package,
            "node": node,
            "npx": npx,
            "docker": docker,
            "docker_available": False,
            "cli_reachable": False,
            "version": None,
            "errors": [],
        }
        if not node:
            status["errors"].append("Node.js >= 18 is required for Shannon (npx workflow)")
        if not npx:
            status["errors"].append("npx is required for Shannon")
        if not docker:
            status["errors"].append("Docker is required for Shannon worker containers")
        else:
            dock = self.runner.run(["docker", "info"], timeout=20)
            status["docker_available"] = dock.ok
            if not dock.ok:
                status["errors"].append("Docker binary found but daemon not usable")

        if npx:
            ver = self.runner.run(["npx", "--yes", self.package, "version", "--json"], timeout=120)
            if ver.ok:
                status["cli_reachable"] = True
                try:
                    payload = json.loads(ver.stdout.strip() or "{}")
                    status["version"] = payload.get("version") or ver.stdout.strip()
                except json.JSONDecodeError:
                    status["version"] = ver.stdout.strip() or "unknown"
            else:
                # Fallback non-json
                ver2 = self.runner.run(["npx", "--yes", self.package, "version"], timeout=120)
                status["cli_reachable"] = ver2.ok
                status["version"] = ver2.stdout.strip() if ver2.ok else None
                if not ver2.ok:
                    status["errors"].append(
                        f"Unable to run Shannon CLI: {(ver.stderr or ver2.stderr)[:400]}"
                    )
        status["healthy"] = bool(status["cli_reachable"]) and not status["errors"]
        # cli_reachable without docker still useful for dry diagnostics
        if status["cli_reachable"] and docker is None:
            status["healthy"] = False
        return status

    def run(self, request: AdapterRequest) -> ExecutionResult:
        execution_id = str(uuid4())
        try:
            self.preflight(request)
        except PermissionError as exc:
            audit_event("shannon.blocked", reason=str(exc), target=request.target)
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="blocked",
                error=str(exc),
            )

        if not request.repo_path:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="Shannon requires -r/--repo (source workspace path)",
            )
        repo = Path(request.repo_path)
        if not repo.exists() or not repo.is_dir():
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error=f"Repository path does not exist or is not a directory: {repo}",
            )

        health = self.healthcheck()
        out_dir = Path(request.output_dir or self.config.reports_dir / f"shannon-{execution_id}")
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path = out_dir / "shannon-run.log"

        if request.dry_run:
            cmd = self._build_start_command(request, out_dir)
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="skipped",
                artifacts={"planned_command": " ".join(cmd), "output_dir": str(out_dir)},
                metadata={"health": health, "dry_run": True},
            )

        if not health.get("cli_reachable"):
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="Shannon CLI is not reachable: " + "; ".join(health.get("errors", [])),
                metadata={"health": health},
            )
        if not health.get("docker_available"):
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="blocked",
                error="Shannon requires a working Docker daemon for worker containers",
                metadata={"health": health},
            )

        # Launch-time destination gate (does not contain Shannon's own workers after start).
        try:
            self.egress_preflight(request)
        except PermissionError as exc:
            audit_event("shannon.blocked", reason=str(exc), target=request.target)
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="blocked",
                error=str(exc),
                metadata={"health": health},
            )

        from core.isolation import load_isolation_policy

        if not load_isolation_policy().allow_shannon_live:
            msg = (
                "Live Shannon runs require PEN_ALLOW_SHANNON_LIVE=1. "
                "Shannon Temporal/Docker workers are not attached to platform "
                "Compose isolation networks; launch-time DNS preflight alone is not "
                "in-engine containment. Prefer dry_run=true or host firewall controls."
            )
            audit_event("shannon.blocked", reason=msg, target=request.target)
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="blocked",
                error=msg,
                metadata={"health": health, "isolation": "shannon_live_gate"},
            )

        cmd = self._build_start_command(request, out_dir)
        audit_event("shannon.start", execution_id=execution_id, command=cmd[:6])
        timeout = request.timeout_seconds or self.config.default_timeout_seconds
        result = self.runner.run(cmd, timeout=timeout, log_path=log_path)
        findings = self._collect_findings(out_dir, execution_id, request.target)
        status = "succeeded" if result.ok else ("timed_out" if result.timed_out else "failed")
        return ExecutionResult(
            tool=self.name,
            execution_id=execution_id,
            status=status,
            findings=findings,
            artifacts={"output_dir": str(out_dir), "log": str(log_path)},
            logs=[result.stdout[-2000:], result.stderr[-2000:]],
            error=None if result.ok else (result.stderr or "Shannon exited non-zero"),
            metadata={"returncode": result.returncode, "health": health},
        )

    def _build_start_command(self, request: AdapterRequest, out_dir: Path) -> list[str]:
        cmd = [
            "npx",
            "--yes",
            self.package,
            "start",
            "-u",
            request.target,
            "-r",
            str(Path(request.repo_path).resolve()),
            "-o",
            str(out_dir.resolve()),
        ]
        if request.config_path:
            cmd.extend(["-c", str(request.config_path)])
        if request.workspace:
            cmd.extend(["-w", request.workspace])
        if request.extra.get("follow"):
            cmd.append("--follow")
        if request.extra.get("validate_model"):
            cmd.append("--validate-model")
        if request.extra.get("validate_auth"):
            cmd.append("--validate-auth")
        if request.extra.get("pipeline_testing"):
            cmd.append("--pipeline-testing")
        return cmd

    def _collect_findings(self, out_dir: Path, execution_id: str, asset: str) -> list:
        findings = []
        # Discover JSON / SARIF artifacts written by Shannon if present.
        for path in sorted(out_dir.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() == ".json" and "sarif" not in path.name.lower():
                findings.extend(self._from_json(path, execution_id, asset))
            elif path.suffix.lower() == ".sarif" or path.name.endswith(".sarif.json"):
                findings.extend(self._from_sarif(path, execution_id, asset))
        return findings

    def _from_json(self, path: Path, execution_id: str, asset: str) -> list:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        items = []
        candidates = []
        if isinstance(data, list):
            candidates = data
        elif isinstance(data, dict):
            for key in ("findings", "results", "vulnerabilities", "issues"):
                if isinstance(data.get(key), list):
                    candidates = data[key]
                    break
        for item in candidates:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or item.get("name") or item.get("ruleId") or "Shannon finding")
            status = str(item.get("status") or "").lower()
            verification = (
                VerificationState.REPRODUCED.value
                if status in {"exploited", "confirmed", "reproduced"}
                else VerificationState.UNVERIFIED.value
            )
            lifecycle = (
                FindingLifecycle.REPRODUCED.value
                if verification == VerificationState.REPRODUCED.value
                else FindingLifecycle.CANDIDATE.value
            )
            items.append(
                normalize_generic_finding(
                    title=title,
                    category=str(item.get("category") or item.get("type") or "unknown"),
                    source_tool=self.name,
                    source_tool_version=self.version_pin,
                    asset=asset,
                    severity=str(item.get("severity") or "info"),
                    evidence=redact_secrets({"source_file": str(path), "summary": item.get("summary")}),
                    reproduction_steps=[str(s) for s in item.get("reproduction") or item.get("steps") or []],
                    remediation=[str(s) for s in item.get("remediation") or []],
                    execution_id=execution_id,
                    verification_state=verification,
                    lifecycle=lifecycle,
                    confidence="high" if verification == VerificationState.REPRODUCED.value else "medium",
                    raw_refs={"path": str(path)},
                    impact=str(item.get("impact") or ""),
                )
            )
        return items

    def _from_sarif(self, path: Path, execution_id: str, asset: str) -> list:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        items = []
        for run in data.get("runs", []) if isinstance(data, dict) else []:
            for result in run.get("results", []) or []:
                rule_id = result.get("ruleId") or "shannon-rule"
                message = ((result.get("message") or {}).get("text")) or rule_id
                level = str(result.get("level") or "note").lower()
                severity = {"error": "high", "warning": "medium", "note": "info", "none": "info"}.get(
                    level, "info"
                )
                items.append(
                    normalize_generic_finding(
                        title=str(message)[:200],
                        category=str(rule_id),
                        source_tool=self.name,
                        source_tool_version=self.version_pin,
                        asset=asset,
                        severity=severity,
                        evidence=redact_secrets({"sarif_file": str(path)}),
                        execution_id=execution_id,
                        verification_state=VerificationState.UNVERIFIED.value,
                        lifecycle=FindingLifecycle.CANDIDATE.value,
                        raw_refs={"path": str(path), "ruleId": rule_id},
                    )
                )
        return items

    def discover_reports(self, directory: str | Path) -> list[str]:
        root = Path(directory)
        if not root.exists():
            return []
        found = []
        for pattern in ("*.md", "*.pdf", "*.json", "*.sarif"):
            found.extend(str(p) for p in root.rglob(pattern))
        return sorted(found)
