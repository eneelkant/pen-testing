"""Environment diagnostics used by doctor scripts and CLI."""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path
from typing import Any

from core.config import PlatformConfig
from core.execution import CommandRunner
from core.ops.retention import parse_retention_days
from integrations.briar import BriarAdapter
from integrations.shannon import ShannonAdapter
from providers import list_provider_status


def collect_diagnostics(config: PlatformConfig) -> dict[str, Any]:
    runner = CommandRunner()
    docker = runner.which("docker")
    compose = None
    docker_info_ok = False
    compose_ok = False
    if docker:
        info = runner.run(["docker", "info"], timeout=20)
        docker_info_ok = info.ok
        # compose v2 plugin
        c1 = runner.run(["docker", "compose", "version"], timeout=20)
        if c1.ok:
            compose = "docker compose"
            compose_ok = True
        else:
            c2 = runner.which("docker-compose")
            if c2:
                compose = c2
                compose_ok = runner.run([c2, "version"], timeout=20).ok

    shannon = ShannonAdapter(config).healthcheck()
    briar = BriarAdapter(config).healthcheck()

    result = {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
        },
        "tools": {
            "python": sys.executable,
            "git": runner.which("git"),
            "node": runner.which("node"),
            "npx": runner.which("npx"),
            "docker": docker,
            "docker_daemon_ok": docker_info_ok,
            "compose": compose,
            "compose_ok": compose_ok,
            "gh": runner.which("gh"),
        },
        "shannon": shannon,
        "briar": briar,
        "providers": list_provider_status(),
        "paths": {
            "work_dir": str(config.work_dir),
            "reports_dir": str(config.reports_dir),
            "scopes_file": str(config.scopes_file),
            "scopes_exists": Path(config.scopes_file).exists(),
        },
        "recommendations": [],
        "retention": _retention_diagnostic(),
    }
    if not docker:
        result["recommendations"].append(
            "Install Docker Engine or Docker Desktop, then re-run doctor. "
            "Shannon requires Docker for worker containers."
        )
    elif not docker_info_ok:
        result["recommendations"].append("Docker is installed but the daemon is not usable. Start Docker and retry.")
    if not compose_ok:
        result["recommendations"].append("Install Docker Compose v2 (`docker compose`).")
    if not result["tools"]["node"]:
        result["recommendations"].append("Install Node.js 18+ for the Shannon npx launcher.")
    if not briar.get("installed"):
        result["recommendations"].append(
            f"Create an isolated venv and install Briar: python3 -m venv .venv-briar && "
            f".venv-briar/bin/pip install '{config.briar_package}'"
        )
    if not Path(config.scopes_file).exists():
        result["recommendations"].append(
            f"Create an authorization registry at {config.scopes_file} before active scans."
        )
    return result


def _retention_diagnostic() -> dict[str, Any]:
    import os

    raw = os.environ.get("PEN_ASSESSMENT_RETENTION_DAYS")
    try:
        days = parse_retention_days(raw)
    except ValueError as exc:
        return {"enabled": False, "error": str(exc)}
    return {"enabled": days is not None, "days": days, "automatic": False}


def run_doctor(config: PlatformConfig) -> int:
    data = collect_diagnostics(config)
    print(json.dumps(data, indent=2))
    # Non-zero if critical orchestration tools missing for active Shannon use
    # Doctor itself should succeed as an informational command.
    return 0
