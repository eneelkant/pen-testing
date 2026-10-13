"""Network-level isolation assertions (Docker), independent of HTTP_PROXY.

Internal Docker networks are the security boundary for scanner workers. Proxy
environment variables are convenience only — workers that ignore them must still
be unable to reach external destinations.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NetworkIsolationStatus:
    name: str
    exists: bool
    internal: bool
    labels: dict[str, str]
    reason: str

    @property
    def ok(self) -> bool:
        return self.exists and self.internal


def _docker_json(args: list[str]) -> Any:
    proc = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "docker failed").strip()[:500])
    return json.loads(proc.stdout or "null")


def inspect_network(name: str) -> NetworkIsolationStatus:
    try:
        data = _docker_json(["network", "inspect", name])
    except RuntimeError as exc:
        return NetworkIsolationStatus(name, False, False, {}, str(exc))
    if not isinstance(data, list) or not data:
        return NetworkIsolationStatus(name, False, False, {}, "empty inspect")
    net = data[0]
    labels = {str(k): str(v) for k, v in (net.get("Labels") or {}).items()}
    internal = bool(net.get("Internal"))
    reason = "internal" if internal else "network is not internal (direct egress may be possible)"
    return NetworkIsolationStatus(name, True, internal, labels, reason)


def assert_network_internal(name: str) -> NetworkIsolationStatus:
    status = inspect_network(name)
    if not status.ok:
        raise PermissionError(
            f"Required isolation network {name!r} is not internal/ready: {status.reason}. "
            "Refusing to start scanner workers (fail closed)."
        )
    return status


def compose_networks_must_be_internal(compose_config: dict[str, Any], names: tuple[str, ...]) -> None:
    """Validate `docker compose config` JSON / dict for internal:true on named nets."""
    networks = compose_config.get("networks") or {}
    for name in names:
        # Compose may prefix; look for exact or suffix match.
        matched = None
        for key, val in networks.items():
            if key == name or key.endswith(name) or (isinstance(val, dict) and val.get("name") == name):
                matched = val if isinstance(val, dict) else {}
                break
        if matched is None:
            raise PermissionError(f"Compose config missing network {name!r}")
        if not bool(matched.get("internal")):
            raise PermissionError(
                f"Compose network {name!r} must set internal: true "
                "(HTTP_PROXY is not a security boundary)"
            )


def required_scanner_networks() -> tuple[str, ...]:
    return (
        os.environ.get("PEN_SCANNER_ISOLATED_NET", "pen-scanner-isolated"),
        os.environ.get("PEN_SCANNER_LIVE_NET", "pen-scanner-live"),
    )


def resolve_project_network_name(
    *,
    project_name: str,
    network_key: str,
    listed_names: list[str],
) -> str:
    """Pick the Compose-project network name; never prefer an unrelated suffix match.

    Prefer, in order:
    1. Exact `{project}_{network_key}` when present in listed_names
    2. Exact `network_key` (explicit compose `name:`)
    3. A single listed name that ends with `_{network_key}` or equals `network_key`

    Multiple ambiguous suffix matches without a project-prefixed hit fail closed.
    """
    project = (project_name or "").strip()
    key = (network_key or "").strip()
    if not key:
        raise PermissionError("network key required for isolation assert")
    names = [n.strip() for n in listed_names if n and n.strip()]
    preferred = f"{project}_{key}" if project else ""
    if preferred and preferred in names:
        return preferred
    if key in names:
        return key
    suffix_hits = [n for n in names if n == key or n.endswith(f"_{key}")]
    if len(suffix_hits) == 1:
        return suffix_hits[0]
    if not suffix_hits:
        raise PermissionError(
            f"Docker network for compose key {key!r} (project {project!r}) not found"
        )
    raise PermissionError(
        f"Ambiguous Docker networks for {key!r}: {suffix_hits!r}. "
        "Refusing to assert isolation against an unrelated network (fail closed)."
    )
