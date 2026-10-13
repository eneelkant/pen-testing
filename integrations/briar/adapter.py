"""Briar adapter — prefers Compose network isolation for live scans."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

from core.execution import CommandRunner
from core.findings import FindingLifecycle, VerificationState, normalize_generic_finding, redact_secrets
from core.isolation import (
    assert_network_internal,
    build_compose_briar_command,
    find_compose_dir,
    load_isolation_policy,
    resolve_project_network_name,
    resolve_briar_exec_mode,
    rewrite_paths_for_compose,
)
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

    def _exec_mode(self) -> str:
        return load_isolation_policy().briar_exec_mode

    def _host_briar_cmd(self, *args: str) -> list[str]:
        briar = self.runner.which("briar")
        if briar:
            return [briar, *args]
        return [self.python_bin, "-m", "briar", *args]

    def _healthcheck_host(self) -> dict[str, Any]:
        status: dict[str, Any] = {
            "tool": self.name,
            "exec_mode": "host",
            "pinned_package": self.package,
            "python": self.python_bin,
            "installed": False,
            "version": None,
            "commands": {},
            "errors": [],
        }
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
                f"Install into an isolated venv: pip install '{self.package}' "
                "or use PEN_BRIAR_EXEC=compose."
            )

        help_res = self.runner.run(self._host_briar_cmd("--help"), timeout=30)
        status["commands"]["help"] = help_res.ok
        if help_res.ok:
            text = (help_res.stdout or "") + (help_res.stderr or "")
            for name in ("setup", "scan", "demo", "serve", "status", "workspaces", "resume"):
                status["commands"][name] = name in text
            scan_help = self.runner.run(self._host_briar_cmd("scan", "--help"), timeout=30)
            scan_text = (scan_help.stdout or "") + (scan_help.stderr or "")
            status["commands"]["scan_quick"] = "--quick" in scan_text
            status["commands"]["scan_deep"] = "--deep" in scan_text
            status["commands"]["scan_url"] = "--url" in scan_text
        elif status["installed"]:
            status["errors"].append("briar package present but CLI help failed")

        status["healthy"] = status["installed"] and status["commands"].get("scan", False)
        return status

    def _healthcheck_compose(self) -> dict[str, Any]:
        status: dict[str, Any] = {
            "tool": self.name,
            "exec_mode": "compose",
            "pinned_package": self.package,
            "docker": False,
            "compose_dir": None,
            "commands": {"scan": True, "demo": True},
            "errors": [],
        }
        docker = self.runner.which("docker")
        if not docker:
            status["errors"].append(
                "docker not found on PATH; Compose Briar execution requires a host Docker CLI "
                "(orchestrator container intentionally has no docker.sock)."
            )
            status["healthy"] = False
            return status
        status["docker"] = True
        try:
            root = find_compose_dir()
            status["compose_dir"] = str(root)
        except FileNotFoundError as exc:
            status["errors"].append(str(exc))
            status["healthy"] = False
            return status

        compose_ver = self.runner.run(["docker", "compose", "version"], timeout=30)
        if not compose_ver.ok:
            status["errors"].append("docker compose plugin unavailable")
            status["healthy"] = False
            return status

        # Config validation proves the worker services exist without starting a scan.
        cfg = self.runner.run(
            [
                "docker",
                "compose",
                "--project-directory",
                str(root),
                "--profile",
                "live-workers",
                "--profile",
                "workers",
                "config",
                "-q",
            ],
            timeout=60,
        )
        if not cfg.ok:
            status["errors"].append(
                "docker compose config failed for workers/live-workers profiles: "
                + (cfg.stderr or cfg.stdout or "unknown error")[:400]
            )
            status["healthy"] = False
            return status

        status["healthy"] = True
        return status

    def healthcheck(self) -> dict[str, Any]:
        try:
            mode = resolve_briar_exec_mode()
        except ValueError as exc:
            return {
                "tool": self.name,
                "healthy": False,
                "errors": [str(exc)],
                "commands": {},
            }
        if mode == "compose":
            return self._healthcheck_compose()
        return self._healthcheck_host()

    def run(self, request: AdapterRequest) -> ExecutionResult:
        execution_id = str(uuid4())
        is_demo = bool(request.extra.get("demo"))
        try:
            exec_mode = resolve_briar_exec_mode()
        except ValueError as exc:
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="blocked",
                error=str(exc),
                metadata={"isolation": "briar_exec_mode"},
            )

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
            cmd = self._build_command(
                request, out_dir, json_out, demo=is_demo, exec_mode=exec_mode, live=not is_demo
            )
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="skipped",
                artifacts={"planned_command": " ".join(cmd), "output_dir": str(out_dir)},
                metadata={
                    "health": health,
                    "dry_run": True,
                    "exec_mode": exec_mode,
                    "network": self._network_label(exec_mode, live=not is_demo),
                },
            )

        if not health.get("healthy"):
            return ExecutionResult(
                tool=self.name,
                execution_id=execution_id,
                status="failed",
                error="Briar is not healthy: " + "; ".join(health.get("errors", [])),
                metadata={"health": health, "exec_mode": exec_mode},
            )

        policy = load_isolation_policy()
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
                    metadata={"health": health, "exec_mode": exec_mode},
                )

            if not policy.allow_briar_live:
                msg = (
                    "Live Briar runs require PEN_ALLOW_BRIAR_LIVE=1. "
                    "Prefer PEN_BRIAR_EXEC=compose (default) so the process runs on "
                    "pen-scanner-live. Host execution additionally requires "
                    "PEN_ALLOW_BRIAR_HOST_NET=1. Launch-time DNS preflight alone is not "
                    "in-engine containment."
                )
                audit_event("briar.blocked", reason=msg, target=request.target)
                return ExecutionResult(
                    tool=self.name,
                    execution_id=execution_id,
                    status="blocked",
                    error=msg,
                    metadata={"health": health, "isolation": "briar_live_gate", "exec_mode": exec_mode},
                )

            if exec_mode == "host" and not policy.allow_briar_host_net:
                msg = (
                    "PEN_BRIAR_EXEC=host places Briar on the operator host network "
                    "(no Compose isolation). Set PEN_ALLOW_BRIAR_HOST_NET=1 to acknowledge, "
                    "or use PEN_BRIAR_EXEC=compose (default) for pen-scanner-live."
                )
                audit_event("briar.blocked", reason=msg, target=request.target)
                return ExecutionResult(
                    tool=self.name,
                    execution_id=execution_id,
                    status="blocked",
                    error=msg,
                    metadata={
                        "health": health,
                        "isolation": "briar_host_net_gate",
                        "exec_mode": exec_mode,
                    },
                )

            if exec_mode == "compose":
                # Network-level fail-closed: pen-scanner-live must be internal.
                # HTTP_PROXY is convenience only and must not be the sole boundary.
                try:
                    net_key = "pen-scanner-live"
                    compose_dir = str(find_compose_dir())
                    created = self.runner.run(
                        [
                            "docker",
                            "compose",
                            "--project-directory",
                            compose_dir,
                            "--profile",
                            "live-workers",
                            "create",
                            "briar-live",
                        ],
                        timeout=120,
                    )
                    if not getattr(created, "ok", False):
                        raise RuntimeError(
                            "docker compose create briar-live failed: "
                            + ((created.stderr or created.stdout or "")[:400])
                        )
                    # Resolve Compose project name so we assert *this* project's network,
                    # not an unrelated host network that merely shares a name suffix.
                    cfg = self.runner.run(
                        [
                            "docker",
                            "compose",
                            "--project-directory",
                            compose_dir,
                            "--profile",
                            "live-workers",
                            "config",
                            "--format",
                            "json",
                        ],
                        timeout=60,
                    )
                    if not getattr(cfg, "ok", False):
                        raise RuntimeError("docker compose config failed while verifying isolation")
                    try:
                        project_name = str(json.loads(cfg.stdout or "{}").get("name") or "pen-testing")
                    except json.JSONDecodeError as exc:
                        raise RuntimeError(f"compose config JSON invalid: {exc}") from exc
                    ls = self.runner.run(
                        [
                            "docker",
                            "network",
                            "ls",
                            "--filter",
                            f"label=com.docker.compose.project={project_name}",
                            "--filter",
                            f"label=com.docker.compose.network={net_key}",
                            "--format",
                            "{{.Name}}",
                        ],
                        timeout=30,
                    )
                    listed = [line.strip() for line in (ls.stdout or "").splitlines() if line.strip()]
                    if not listed:
                        # Fallback: unfiltered names (older engines / label gaps).
                        ls_all = self.runner.run(
                            ["docker", "network", "ls", "--format", "{{.Name}}"],
                            timeout=30,
                        )
                        listed = [
                            line.strip()
                            for line in (ls_all.stdout or "").splitlines()
                            if line.strip()
                        ]
                    resolved = resolve_project_network_name(
                        project_name=project_name,
                        network_key=net_key,
                        listed_names=listed,
                    )
                    assert_network_internal(resolved)
                except PermissionError as exc:
                    audit_event("briar.blocked", reason=str(exc), target=request.target)
                    return ExecutionResult(
                        tool=self.name,
                        execution_id=execution_id,
                        status="blocked",
                        error=str(exc),
                        metadata={
                            "health": health,
                            "isolation": "briar_network_internal",
                            "exec_mode": exec_mode,
                        },
                    )
                except Exception as exc:  # noqa: BLE001 — fail closed on infra errors
                    msg = f"Unable to verify Briar network isolation: {exc}"
                    audit_event("briar.blocked", reason=msg, target=request.target)
                    return ExecutionResult(
                        tool=self.name,
                        execution_id=execution_id,
                        status="blocked",
                        error=msg,
                        metadata={
                            "health": health,
                            "isolation": "briar_network_internal",
                            "exec_mode": exec_mode,
                        },
                    )

        live = not is_demo
        cmd = self._build_command(
            request, out_dir, json_out, demo=is_demo, exec_mode=exec_mode, live=live
        )
        audit_event(
            "briar.start",
            execution_id=execution_id,
            demo=is_demo,
            mode=request.mode,
            exec_mode=exec_mode,
            network=self._network_label(exec_mode, live=live),
        )
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
            metadata={
                "returncode": result.returncode,
                "health": health,
                "demo": is_demo,
                "exec_mode": exec_mode,
                "network": self._network_label(exec_mode, live=live),
            },
        )

    @staticmethod
    def _network_label(exec_mode: str, *, live: bool) -> str:
        if exec_mode == "host":
            return "host"
        return "pen-scanner-live" if live else "pen-scanner-isolated"

    def _build_inner_args(
        self, request: AdapterRequest, out_dir: Path, json_out: Path, *, demo: bool
    ) -> list[str]:
        if demo:
            return ["demo"]
        mode = (request.mode or "standard").lower()
        args = ["scan", "-u", request.target, "-o", str(out_dir), "--output-json", str(json_out)]
        if request.repo_path:
            args.extend(["-r", str(request.repo_path)])
        if request.config_path:
            args.extend(["-c", str(request.config_path)])
        if mode == "quick":
            args.append("--quick")
        elif mode == "deep":
            args.append("--deep")
        if request.extra.get("provider"):
            args.extend(["-p", str(request.extra["provider"])])
        if request.extra.get("lang"):
            args.extend(["--lang", str(request.extra["lang"])])
        return args

    def _build_command(
        self,
        request: AdapterRequest,
        out_dir: Path,
        json_out: Path,
        *,
        demo: bool,
        exec_mode: str,
        live: bool,
    ) -> list[str]:
        inner = self._build_inner_args(request, out_dir, json_out, demo=demo)
        if exec_mode == "host":
            return self._host_briar_cmd(*inner)
        container_args = rewrite_paths_for_compose(inner, out_dir=out_dir, json_out=json_out)
        return build_compose_briar_command(
            briar_args=container_args,
            out_dir=out_dir,
            live=live and not demo,
        )

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
