"""MCP server entrypoint (stdio only).

Exposes a constrained tool surface over the existing platform APIs.
Does not provide arbitrary shell, filesystem, or network access.
"""

from __future__ import annotations

from typing import Any, Literal

from mcp.server import MCPServer

from core import __version__
from mcp_server import service

mcp = MCPServer(
    name="pen-testing",
    version=__version__,
    instructions=(
        "Authorized security-testing orchestration platform. "
        "For remote/web targets, call validate_target_scope before a live run. "
        "For local source scanners (gitleaks, trivy, checkov, mobsfscan), target paths "
        "must remain inside configured workspace/report roots; do not use the URL scope "
        "validator for a filesystem path. Live runs still require confirm_authorized=true. "
        "Never expand network scope silently. Prefer dry_run=true and local fixtures."
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
    tool: Literal["shannon", "briar", "headers", "gitleaks", "trivy", "checkov", "mobsfscan"],
    target: str,
    category: Literal["passive", "active", "dast", "pentest", "dynamic"] = "active",
    mode: Literal["quick", "standard", "deep"] = "standard",
    repo_path: str | None = None,
    dry_run: bool = True,
    confirm_authorized: bool = False,
    demo: bool = False,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Run a registered adapter only after its target-specific safety checks.

    Defaults to dry_run=true. Remote active targets require scope validation first.
    Local source adapters require a confined workspace/report path. Every non-dry-run
    assessment requires confirm_authorized=true; this flag does not bypass path or
    remote scope controls.
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
