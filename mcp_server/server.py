"""MCP server entrypoint (stdio by default).

Exposes a constrained tool surface over the existing platform APIs.
Does not provide arbitrary shell, filesystem, or network access.
"""

from __future__ import annotations

from typing import Any, Literal

from mcp.server import MCPServer

from mcp_server import service

mcp = MCPServer(
    name="pen-testing",
    version="0.2.0a10",
    instructions=(
        "Authorized security-testing orchestration platform. "
        "Always call validate_target_scope before run_security_assessment with dry_run=false. "
        "Never expand scope silently. Prefer dry_run=true and local fixtures."
    ),
)


@mcp.tool()
def platform_status() -> dict[str, Any]:
    """Inspect installed components and platform health (non-destructive)."""
    return service.platform_status()


@mcp.tool()
def check_dependencies() -> dict[str, Any]:
    """Identify missing or incompatible dependencies without installing anything."""
    return service.check_dependencies()


@mcp.tool()
def validate_target_scope(
    target: str,
    category: Literal["passive", "active", "dast", "pentest", "dynamic"] = "active",
) -> dict[str, Any]:
    """Validate a proposed target against the authorization registry."""
    return service.validate_target_scope(target, category=category)


@mcp.tool()
def list_integrations() -> dict[str, Any]:
    """Report installed scanners and their health/capability status."""
    return service.list_integrations()


@mcp.tool()
def run_local_diagnostics() -> dict[str, Any]:
    """Run non-destructive local health diagnostics."""
    return service.run_local_diagnostics()


@mcp.tool()
def run_security_assessment(
    tool: Literal["shannon", "briar", "headers", "gitleaks", "trivy"],
    target: str,
    category: Literal["passive", "active", "dast", "pentest", "dynamic"] = "active",
    mode: Literal["quick", "standard", "deep"] = "standard",
    repo_path: str | None = None,
    dry_run: bool = True,
    confirm_authorized: bool = False,
    demo: bool = False,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Start an assessment only after authorization/safety checks.

    Defaults to dry_run=true. For live runs set dry_run=false and
    confirm_authorized=true after validate_target_scope succeeds.
    """
    return service.run_security_assessment(
        tool=tool,
        target=target,
        category=category,
        mode=mode,
        repo_path=repo_path,
        dry_run=dry_run,
        confirm_authorized=confirm_authorized,
        demo=demo,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
def get_assessment_status(assessment_id: str) -> dict[str, Any]:
    """Inspect a previously started assessment."""
    return service.get_assessment_status(assessment_id)


@mcp.tool()
def list_findings(assessment_id: str) -> dict[str, Any]:
    """Retrieve normalized findings from a completed assessment."""
    return service.list_findings(assessment_id)


@mcp.tool()
def export_report(assessment_id: str, outdir: str | None = None) -> dict[str, Any]:
    """Generate Markdown/JSON/SARIF drafts from validated assessment results."""
    return service.export_report(assessment_id, outdir=outdir)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
