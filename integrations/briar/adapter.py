"""Briar adapter — invokes briar-pentest CLI in an isolated interpreter/container."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.execution import CommandRunner
from core.findings import FindingLifecycle, VerificationState, normalize_generic_finding, redact_secrets
from core.logging import audit_event
from core.results import ExecutionResult
from integrations.base import AdapterRequest, SecurityAdapter


class BriarAdapter(SecurityAdapter):
    name = "briar"
    version_pin = "0.4.62"
    requires_active_scope = True
    requires_egress_policy = True

    def __init__(self, *args, runner: CommandRunner | None = None, python_bin: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.runner = runner or CommandRunner(max_log_bytes=self.config.max_log_bytes)
        self.python_bin = python_bin or os.environ.get("PEN_BRIAR_PYTHON") or sys.executable
        self.package = self.config.briar_package

    def _briar_cmd(self, *args: str) -> list[str]:
        # Prefer installed console script; fall back to python -m briar
        briar = self.runner.which("briar")
        if briar:
            return [briar, *args]
        return [self.python_bin, "-m", "briar", *args]

    def healthcheck(self) -> dict[str, Any]:
        status: dict[str, Any] = {
            "tool": self.name,
            "pinned_package": self.package,
            "python": self.python_bin,
            "installed": False,
            "version": None,
            "commands": {},
            "errors": [],
        }
        # Detect package
        detect = self.runner.run(
            [
                self.python_bin,
                "-c",
                "import importlib.metadata as m; print(m.version('briar-pentest'))",
            ],
            timeout=30,
        )
        if detect.ok:
            status["installed"] = True
            status["version"] = detect.stdout.strip()
        else:
            status["errors"].append(
                f"briar-pentest not installed in {self.python_bin}. "
                f"Install into an isolated venv: pip install '{self.package}'"
            )

        help_res = self.runner.run(self._briar_cmd("--help"), timeout=30)
        status["commands"]["help"] = help_res.ok
        if help_res.ok:
            text = (help_res.stdout or "") + (help_res.stderr or "")
            for name in ("setup", "scan", "demo", "serve", "status", "workspaces", "resume"):
                status["commands"][name] = name in text
            # Confirm scan flags
            scan_help = self.runner.run(self._briar_cmd("scan", "--help"), timeout=30)
            scan_text = (scan_help.stdout or "") + (scan_help.stderr or "")
            status["commands"]["scan_quick"] = "--quick" in scan_text
            status["commands"]["scan_deep"] = "--deep" in scan_text
            status["commands"]["scan_url"] = "--url" in scan_text
        elif status["installed"]:
            status["errors"].append("briar package present but CLI help failed")

        status["healthy"] = status["installed"] and status["commands"].get("scan", False)
        return status

    def run(self, request: AdapterRequest) -> ExecutionResult:
        execution_id = str(uuid4())
        # Local demo mode does not require external target authorization.
        is_demo = bool(request.extra.get("demo"))
        if not is_demo:
            try:
                self.preflight(request)
            except PermissionError as exc:
                audit_event("briar.blocked", reason=str(exc), target=request.target)
                return ExecutionResult(
                    tool=self.name,
                    execution_id=execution_id,
                    status="blocked",
                    error=str(exc),
                )

        health = self.healthcheck()
        out_dir = Path(request.output_dir or self.config.reports_dir / f"briar-{execution_id}")
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path = out_dir / "briar-run.log"
        json_out = out_dir / "findings.json"

        if request.dry_run:
            cmd = self._build_command(request, out_dir, json_out, demo=is_demo)
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="skipped",
                artifacts={"planned_command": " ".join(cmd), "output_dir": str(out_dir)},
                metadata={"health": health, "dry_run": True},
            )

        if not health.get("healthy"):
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="Briar is not healthy: " + "; ".join(health.get("errors", [])),
                metadata={"health": health},
            )

        if not is_demo:
            try:
                self.egress_preflight(request)
            except PermissionError as exc:
                audit_event("briar.blocked", reason=str(exc), target=request.target)
                return ExecutionResult(
                    tool=self.name,
                    execution_id=execution_id,
                    status="blocked",
                    error=str(exc),
                    metadata={"health": health},
                )

            from core.isolation import load_isolation_policy

            if not load_isolation_policy().allow_briar_live:
                msg = (
                    "Live Briar runs require PEN_ALLOW_BRIAR_LIVE=1. "
                    "Host-invoked Briar is not attached to platform Compose isolation "
                    "networks; launch-time DNS preflight alone is not in-engine "
                    "containment. Prefer dry_run=true, briar demo, or Compose "
                    "`live-workers` with host firewall controls."
                )
                audit_event("briar.blocked", reason=msg, target=request.target)
                return ExecutionResult(
                    tool=self.name,
                    execution_id=execution_id,
                    status="blocked",
                    error=msg,
                    metadata={"health": health, "isolation": "briar_live_gate"},
                )

        cmd = self._build_command(request, out_dir, json_out, demo=is_demo)
        audit_event("briar.start", execution_id=execution_id, demo=is_demo, mode=request.mode)
        timeout = request.timeout_seconds or self.config.default_timeout_seconds
        result = self.runner.run(cmd, timeout=timeout, log_path=log_path)
        findings = self._load_findings(json_out, execution_id, request.target or "demo")
        status = "succeeded" if result.ok else ("timed_out" if result.timed_out else "failed")
        return ExecutionResult(
            tool=self.name,
            execution_id=execution_id,
            status=status,
            findings=findings,
            artifacts={"output_dir": str(out_dir), "log": str(log_path), "json": str(json_out)},
            logs=[result.stdout[-2000:], result.stderr[-2000:]],
            error=None if result.ok else (result.stderr or "Briar exited non-zero"),
            metadata={"returncode": result.returncode, "health": health, "demo": is_demo},
        )

    def _build_command(
        self, request: AdapterRequest, out_dir: Path, json_out: Path, *, demo: bool
    ) -> list[str]:
        if demo:
            return self._briar_cmd("demo")
        mode = (request.mode or "standard").lower()
        cmd = self._briar_cmd("scan", "-u", request.target, "-o", str(out_dir), "--output-json", str(json_out))
        if request.repo_path:
            cmd.extend(["-r", str(request.repo_path)])
        if request.config_path:
            cmd.extend(["-c", str(request.config_path)])
        if mode == "quick":
            cmd.append("--quick")
        elif mode == "deep":
            cmd.append("--deep")
        if request.extra.get("provider"):
            cmd.extend(["-p", str(request.extra["provider"])])
        if request.extra.get("lang"):
            cmd.extend(["--lang", str(request.extra["lang"])])
        return cmd

    def _load_findings(self, path: Path, execution_id: str, asset: str) -> list:
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        candidates = data if isinstance(data, list) else data.get("findings", []) if isinstance(data, dict) else []
        items = []
        for item in candidates:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or item.get("name") or "Briar finding")
            confirmed = bool(item.get("confirmed") or item.get("exploited") or item.get("validated"))
            verification = (
                VerificationState.REPRODUCED.value if confirmed else VerificationState.UNVERIFIED.value
            )
            items.append(
                normalize_generic_finding(
                    title=title,
                    category=str(item.get("type") or item.get("category") or "unknown"),
                    source_tool=self.name,
                    source_tool_version=status_version(self),
                    asset=asset,
                    severity=str(item.get("severity") or "info"),
                    evidence=redact_secrets({"summary": item.get("description") or item.get("summary")}),
                    reproduction_steps=[str(s) for s in item.get("poc") or item.get("steps") or []],
                    remediation=[str(s) for s in item.get("remediation") or []],
                    references=[str(s) for s in item.get("references") or []],
                    execution_id=execution_id,
                    verification_state=verification,
                    lifecycle=(
                        FindingLifecycle.REPRODUCED.value
                        if confirmed
                        else FindingLifecycle.CANDIDATE.value
                    ),
                    confidence="high" if confirmed else "medium",
                    impact=str(item.get("impact") or ""),
                    severity_rationale=str(item.get("cvss") or item.get("severity_rationale") or ""),
                    raw_refs={"path": str(path)},
                )
            )
        return items


def status_version(adapter: BriarAdapter) -> str:
    return adapter.version_pin
