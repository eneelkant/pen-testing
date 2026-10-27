"""Curated capability metadata for adapters actually implemented in this repository.

This registry describes supported behavior; it does not itself grant authorization,
install a scanner, or imply that planned integrations are available.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TargetType(str, Enum):
    """Shared target vocabulary. An enum member does not imply current tool support."""

    WEB_URL = "web_url"
    API_URL = "api_url"
    OPENAPI_DOCUMENT = "openapi_document"
    GRAPHQL_ENDPOINT = "graphql_endpoint"
    LOCAL_SOURCE_PATH = "local_source_path"
    HOST = "host"
    CIDR = "cidr"
    ANDROID_ARTIFACT = "android_artifact"
    IOS_ARTIFACT = "ios_artifact"
    ANDROID_DEVICE = "android_device"
    IOS_DEVICE = "ios_device"


class ScanMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    STATIC = "static"
    SOURCE_INFORMED = "source_informed"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"


@dataclass(frozen=True, slots=True)
class ToolCapability:
    """Immutable metadata for one implemented adapter."""

    id: str
    display_name: str
    adapter_module: str
    target_types: tuple[TargetType, ...]
    modes: tuple[ScanMode, ...]
    requires_authorization: bool
    network_profile: str
    dependencies: tuple[str, ...]
    license: str
    upstream_url: str
    version_pin: str
    limitations: tuple[str, ...] = ()
    status: str = "integrated"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly, stable representation."""
        return {
            "id": self.id,
            "display_name": self.display_name,
            "adapter_module": self.adapter_module,
            "target_types": [target.value for target in self.target_types],
            "modes": [mode.value for mode in self.modes],
            "requires_authorization": self.requires_authorization,
            "network_profile": self.network_profile,
            "dependencies": list(self.dependencies),
            "license": self.license,
            "upstream_url": self.upstream_url,
            "version_pin": self.version_pin,
            "limitations": list(self.limitations),
            "status": self.status,
        }


# Keep this list limited to adapters wired into the current CLI/MCP runtime.
# Candidate integrations are tracked in docs/CAPABILITY_REGISTRY.md and are not
# reported as integrated until working adapters and tests have landed.
TOOL_CAPABILITIES: tuple[ToolCapability, ...] = (
    ToolCapability(
        id="briar",
        display_name="Briar",
        adapter_module="integrations.briar.adapter.BriarAdapter",
        target_types=(TargetType.WEB_URL,),
        modes=(ScanMode.ACTIVE, ScanMode.SOURCE_INFORMED),
        requires_authorization=True,
        network_profile="Dedicated environment/container; live execution and host networking have separate gates.",
        dependencies=("Python >=3.10", "briar-pentest==0.4.62", "Docker recommended for isolation"),
        license="AGPL-3.0",
        upstream_url="https://github.com/Stiimy/briar",
        version_pin="briar-pentest==0.4.62",
        limitations=(
            "Optional dependency; current integration is web-oriented.",
            "Does not establish complete in-engine containment of every network action.",
        ),
    ),
    ToolCapability(
        id="gitleaks",
        display_name="Gitleaks",
        adapter_module="integrations.scanners.gitleaks.GitleaksAdapter",
        target_types=(TargetType.LOCAL_SOURCE_PATH,),
        modes=(ScanMode.STATIC,),
        requires_authorization=False,
        network_profile="Local source analysis; Docker fallback uses a network-disabled container. Host-binary behavior follows operator host policy.",
        dependencies=("gitleaks binary or Docker",),
        license="MIT",
        upstream_url="https://github.com/gitleaks/gitleaks",
        version_pin="Digest-pinned image; see core.supply_chain.images.PINNED_IMAGES.",
        limitations=("Scans configured local paths; it is not a remote website scanner.",),
    ),
    ToolCapability(
        id="headers",
        display_name="HTTP security headers",
        adapter_module="integrations.scanners.headers.HeadersAdapter",
        target_types=(TargetType.WEB_URL,),
        modes=(ScanMode.PASSIVE,),
        requires_authorization=True,
        network_profile="HTTP(S) GET; redirects are not automatically followed and must pass redirect/scope validation.",
        dependencies=("Python standard library",),
        license="Apache-2.0 (repository)",
        upstream_url="https://github.com/eneelkant/pen-testing",
        version_pin="In-repository adapter; see integrations/scanners/headers.py.",
        limitations=("Checks selected response headers only; it is not a TLS grader or DAST engine.",),
    ),
    ToolCapability(
        id="shannon",
        display_name="Shannon",
        adapter_module="integrations.shannon.adapter.ShannonAdapter",
        target_types=(TargetType.WEB_URL, TargetType.API_URL),
        modes=(ScanMode.ACTIVE, ScanMode.SOURCE_INFORMED),
        requires_authorization=True,
        network_profile="Docker worker with live execution gates; verify worker egress controls before live use.",
        dependencies=("Node.js and npx", "Docker", "configured LLM provider", "source repository for source-informed testing"),
        license="AGPL-3.0-only",
        upstream_url="https://github.com/KeygraphHQ/shannon",
        version_pin="@keygraph/shannon@3.4.0",
        limitations=(
            "Active and potentially mutative; explicitly confirm authorization.",
            "Do not infer complete redirect/DNS containment solely from launch-time checks.",
        ),
    ),
    ToolCapability(
        id="checkov",
        display_name="Checkov",
        adapter_module="integrations.scanners.checkov.CheckovAdapter",
        target_types=(TargetType.LOCAL_SOURCE_PATH,),
        modes=(ScanMode.STATIC, ScanMode.CONFIGURATION),
        requires_authorization=False,
        network_profile="Local IaC/configuration analysis; --skip-download disables Checkov platform downloads.",
        dependencies=("checkov==3.3.29 optional extra",),
        license="Apache-2.0",
        upstream_url="https://github.com/bridgecrewio/checkov",
        version_pin="3.3.29",
        limitations=(
            "Optional executable; exact distribution version is checked at runtime.",
            "Only local source/configuration scanning is exposed; no remote cloud account is scanned.",
        ),
    ),
    ToolCapability(
        id="mobsfscan",
        display_name="MobSFScan",
        adapter_module="integrations.scanners.mobsfscan.MobSFScanAdapter",
        target_types=(TargetType.LOCAL_SOURCE_PATH,),
        modes=(ScanMode.STATIC,),
        requires_authorization=False,
        network_profile="Local mobile source-code pattern scanning; Semgrep telemetry disabled for the child process.",
        dependencies=("mobsfscan==1.0.1 optional extra",),
        license="LGPL-3.0-or-later",
        upstream_url="https://github.com/MobSF/mobsfscan",
        version_pin="1.0.1",
        limitations=(
            "Scans source code patterns, not APK/IPA binaries or runtime/device behavior.",
            "Optional executable; exact distribution version is checked at runtime.",
        ),
    ),
    ToolCapability(
        id="trivy",
        display_name="Trivy filesystem scanner",
        adapter_module="integrations.scanners.trivy.TrivyAdapter",
        target_types=(TargetType.LOCAL_SOURCE_PATH,),
        modes=(ScanMode.STATIC, ScanMode.DEPENDENCY, ScanMode.CONFIGURATION),
        requires_authorization=False,
        network_profile="Local filesystem analysis; Docker fallback uses a network-disabled container and cached database.",
        dependencies=("trivy binary or Docker",),
        license="Apache-2.0",
        upstream_url="https://github.com/aquasecurity/trivy",
        version_pin="Digest-pinned image; see core.supply_chain.images.PINNED_IMAGES.",
        limitations=(
            "Current adapter is filesystem-oriented; it does not imply host, network, or all image-scan modes are wired into the CLI.",
        ),
    ),
)

CAPABILITIES_BY_ID: dict[str, ToolCapability] = {
    capability.id: capability for capability in TOOL_CAPABILITIES
}


def list_capabilities() -> list[dict[str, object]]:
    """List currently implemented capabilities in deterministic order."""
    return [capability.to_dict() for capability in TOOL_CAPABILITIES]


def get_capability(tool_id: str) -> ToolCapability:
    """Return metadata for an implemented adapter; reject unknown/planned tools."""
    normalized = (tool_id or "").strip().lower()
    try:
        return CAPABILITIES_BY_ID[normalized]
    except KeyError as exc:
        raise KeyError(f"No integrated capability is registered for: {normalized or '<empty>'}") from exc
