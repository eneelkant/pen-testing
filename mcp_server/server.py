"""MCP server entrypoint (stdio only).

Exposes a constrained tool surface over the existing platform APIs.
Does not provide arbitrary shell, filesystem, or network access.
"""

from __future__ import annotations

from typing import Any, Literal

from core import __version__
from mcp.server.mcpserver import MCPServer

from mcp_server import service

mcp = MCPServer(
    name="pen-testing",
    version=__version__,
    instructions=(
        "Authorized security-testing orchestration platform. "
        "For remote/web targets, call validate_target_scope before a live assessment. "
        "Use plan_assessment to preview work without launching scanners. "
        "Live runs require authorize_assessment (bound approval_id) plus confirm_authorized=true. "
        "Local source scanners require paths confined to configured work/report roots and do not use URL scope validation. "
        "Never expand network scope silently. Prefer dry_run=true and local fixtures. "
        "Do not probe Zoho or other third-party hosts unless they are explicitly listed in the authorization registry."
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
def plan_assessment(
    tool: Literal["shannon", "briar", "headers", "gitleaks", "trivy", "checkov", "mobsfscan"],
    target: str,
    category: Literal["passive", "active", "dast", "pentest", "dynamic"] = "active",
    mode: Literal["quick", "standard", "deep"] = "standard",
    profile_id: str | None = None,
    repo_path: str | None = None,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Create an assessment plan without launching any scanner."""
    return service.plan_assessment(
        tool=tool,
        target=target,
        category=category,
        mode=mode,
        profile_id=profile_id,
        repo_path=repo_path,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool()
def authorize_assessment(
    tool: Literal["shannon", "briar", "headers", "gitleaks", "trivy", "checkov", "mobsfscan"],
    target: str,
    category: Literal["passive", "active", "dast", "pentest", "dynamic"] = "active",
    mode: Literal["quick", "standard", "deep"] = "standard",
    profile_id: str | None = None,
    ttl_seconds: int = 900,
    confirm_authorized: bool = False,
) -> dict[str, Any]:
    """Issue a bound, single-use live-execution approval after scope and profile checks."""
    return service.authorize_assessment(
        tool=tool,
        target=target,
        category=category,
        mode=mode,
        profile_id=profile_id,
        ttl_seconds=ttl_seconds,
        confirm_authorized=confirm_authorized,
    )


@mcp.tool()
def run_security_assessment(
    tool: Literal["shannon", "briar", "headers", "gitleaks", "trivy", "checkov", "mobsfscan"],
    target: str,
    category: Literal["passive", "active", "dast", "pentest", "dynamic"] = "active",
    mode: Literal["quick", "standard", "deep"] = "standard",
    repo_path: str | None = None,
    dry_run: bool = True,
    confirm_authorized: bool = False,
    demo: bool = False,
    timeout_seconds: int = 120,
    profile_id: str | None = None,
    approval_id: str | None = None,
) -> dict[str, Any]:
    """Start an assessment only after authorization/safety checks.

    Defaults to dry_run=true. For live runs set dry_run=false, confirm_authorized=true,
    and supply a bound approval_id from authorize_assessment.
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
        profile_id=profile_id,
        approval_id=approval_id,
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


def assert_supported_transport(transport: str) -> None:
    """Refuse every transport except local stdio.

    SSE and streamable HTTP would publish privileged tools with no authentication.
    """
    if transport != "stdio":
        raise PermissionError(
            f"MCP transport {transport!r} is refused. This server speaks stdio only "
            "and does not authenticate remote clients."
        )


def _run_stdio_only(transport: str = "stdio", **kwargs: Any) -> None:
    assert_supported_transport(transport)
    if kwargs:
        raise PermissionError("Remote MCP listener options are refused")
    _mcp_run(transport="stdio")


_mcp_run = mcp.run
mcp.run = _run_stdio_only  # type: ignore[method-assign]


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
