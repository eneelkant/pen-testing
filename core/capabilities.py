"""Static capability registry for the integrations actually supported by this checkout.

The registry is descriptive metadata, not an authorization decision and not proof that
an external executable is installed. Runtime availability must come from adapter
health checks. Planned entries are roadmap hints only and are never dispatchable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Capability:
    tool_id: str
    display_name: str
    status: str
    target_types: tuple[str, ...]
    modes: tuple[str, ...]
    version: str
    license: str
    isolation: str
    description: str
    source_url: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["target_types"] = list(self.target_types)
        result["modes"] = list(self.modes)
        result["implemented"] = self.status == "integrated"
        return result


_CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        tool_id="shannon",
        display_name="Shannon",
        status="integrated",
        target_types=("web_url",),
        modes=("active",),
        version="3.4.0",
        license="AGPL-3.0-only",
        isolation="Upstream Docker worker; see docs/SCANNER_ISOLATION.md",
        description="AI-assisted web assessment; schema-driven API testing is not provided by this registry entry.",
        source_url="https://github.com/KeygraphHQ/shannon",
        notes="Requires compatible Node.js/npx and Docker runtime; live execution is scope-gated.",
    ),
    Capability(
        tool_id="briar",
        display_name="Briar",
        status="integrated",
        target_types=("web_url",),
        modes=("active",),
        version="0.4.62",
        license="AGPL-3.0",
        isolation="Dedicated virtual environment or isolated Compose worker",
        description="AI-assisted black-box web assessment with optional source-informed operation.",
        source_url="https://github.com/Stiimy/briar",
        notes="Runtime health check determines whether the pinned package and worker prerequisites are available.",
    ),
    Capability(
        tool_id="headers",
        display_name="Security headers checker",
        status="integrated",
        target_types=("web_url",),
        modes=("passive",),
        version="0.1.0",
        license="Apache-2.0",
        isolation="In-process passive HTTP GET with redirect handling and destination policy",
        description="Checks a limited set of HTTP response security headers.",
        source_url="https://github.com/eneelkant/pen-testing",
        notes="Not a comprehensive web scanner and does not grade TLS.",
    ),
    Capability(
        tool_id="gitleaks",
        display_name="Gitleaks",
        status="integrated",
        target_types=("source_path",),
        modes=("static",),
        version="configured by the pinned adapter/image",
        license="MIT",
        isolation="Read-only source path or pinned scanner container",
        description="Detects likely secrets in source trees and repository content.",
        source_url="https://github.com/gitleaks/gitleaks",
        notes="A clean result does not prove that a repository contains no secrets.",
    ),
    Capability(
        tool_id="trivy",
        display_name="Trivy",
        status="integrated",
        target_types=("source_path",),
        modes=("static", "dependency", "configuration"),
        version="configured by the pinned adapter/image",
        license="Apache-2.0",
        isolation="Read-only source path or pinned scanner container",
        description="Filesystem, dependency and supported configuration analysis.",
        source_url="https://github.com/aquasecurity/trivy",
        notes="Image vulnerability release gates remain independently enforced.",
    ),
    Capability(
        tool_id="zap",
        display_name="OWASP ZAP",
        status="planned",
        target_types=("web_url", "api_url"),
        modes=("passive", "active"),
        version="not selected",
        license="Apache-2.0",
        isolation="Isolated worker; policy-controlled automation plan",
        description="Planned web/API DAST adapter beginning with passive baseline checks.",
        source_url="https://github.com/zaproxy/zaproxy",
        notes="Not available for dispatch until an adapter, tests and runtime isolation are merged.",
    ),
    Capability(
        tool_id="nuclei",
        display_name="Nuclei",
        status="planned",
        target_types=("web_url", "api_url", "host"),
        modes=("active",),
        version="not selected",
        license="MIT",
        isolation="Isolated worker with pinned engine and reviewed template policy",
        description="Planned template-driven security checks.",
        source_url="https://github.com/projectdiscovery/nuclei",
        notes="Templates and their integrity/licensing need separate review; arbitrary templates are not enabled.",
    ),
    Capability(
        tool_id="schemathesis",
        display_name="Schemathesis",
        status="planned",
        target_types=("api_url", "openapi_document", "graphql_url"),
        modes=("api_schema",),
        version="not selected",
        license="MIT (verify selected release)",
        isolation="Isolated test worker with exact API origin and request limits",
        description="Planned schema-based API test generation.",
        source_url="https://github.com/schemathesis/schemathesis",
        notes="Not an integrated scanner yet; every generated request must remain within approved API scope.",
    ),
    Capability(
        tool_id="mobsf",
        display_name="MobSF",
        status="planned",
        target_types=("android_artifact", "ios_artifact"),
        modes=("static", "dynamic"),
        version="not selected",
        license="GPL-3.0",
        isolation="Local isolated service; no public administrative/API exposure",
        description="Planned mobile-app analysis orchestration, subject to artifact and platform support.",
        source_url="https://github.com/MobSF/Mobile-Security-Framework-MobSF",
        notes="Static and dynamic support differ by platform; confirm selected release formats and licensing before bundling.",
    ),
    Capability(
        tool_id="nmap",
        display_name="Nmap",
        status="planned",
        target_types=("host", "cidr"),
        modes=("network",),
        version="not selected",
        license="NPSL / verify exact release terms",
        isolation="Dedicated worker with explicit host/CIDR and port policy",
        description="Planned authorized network service discovery and assessment.",
        source_url="https://github.com/nmap/nmap",
        notes="CIDR support is a schema capability only; no network scan is implemented by this entry.",
    ),
    Capability(
        tool_id="checkov",
        display_name="Checkov",
        status="planned",
        target_types=("source_path",),
        modes=("static", "configuration"),
        version="not selected",
        license="Apache-2.0 (verify selected release)",
        isolation="Read-only configured workspace",
        description="Planned infrastructure-as-code and configuration scanning.",
        source_url="https://github.com/bridgecrewio/checkov",
        notes="Not available for dispatch until implemented and tested.",
    ),
    Capability(
        tool_id="testssl",
        display_name="testssl.sh",
        status="planned",
        target_types=("host", "web_url"),
        modes=("passive", "tls"),
        version="not selected",
        license="GPL-2.0 (verify selected release)",
        isolation="Isolated worker constrained to an authorized host and port",
        description="Planned TLS posture assessment.",
        source_url="https://github.com/testssl/testssl.sh",
        notes="Not a replacement for authorization or network egress controls.",
    ),
    Capability(
        tool_id="semgrep",
        display_name="Semgrep",
        status="planned",
        target_types=("source_path",),
        modes=("static",),
        version="not selected",
        license="Engine and rules require separate review",
        isolation="Read-only configured workspace",
        description="Candidate static-analysis adapter.",
        source_url="https://github.com/semgrep/semgrep",
        notes="Review engine and rule-set terms individually; do not bundle non-redistributable rules by default.",
    ),
)

_BY_ID = {item.tool_id: item for item in _CAPABILITIES}


def list_capabilities(*, include_planned: bool = False) -> list[dict[str, Any]]:
    """Return descriptive capabilities, excluding planned integrations by default."""
    return [
        item.to_dict()
        for item in _CAPABILITIES
        if include_planned or item.status == "integrated"
    ]


def get_capability(tool_id: str) -> dict[str, Any] | None:
    """Return registry metadata for a tool, or None if it is not registered."""
    item = _BY_ID.get((tool_id or "").strip().lower())
    return item.to_dict() if item else None


def integrated_tool_ids() -> set[str]:
    """Return tools with existing in-repository adapters; runtime health is separate."""
    return {item.tool_id for item in _CAPABILITIES if item.status == "integrated"}
