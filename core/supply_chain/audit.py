"""Compare runtime dependencies with requirement pins and the SBOM.

Findings are local metadata issues. They are not CVE records.
"""

from __future__ import annotations

from pathlib import Path

from core.supply_chain.sbom import (
    build_sbom,
    load_requirement_file,
    load_requirements,
    runtime_dependency_names,
)


def audit_dependencies(root: Path) -> dict:
    requirements = load_requirements(root)
    by_name = {item.name: item for item in requirements}
    base_names = {
        item.name for item in load_requirement_file(root / "requirements/base.txt", "required")
    }
    findings: list[dict] = []
    for name, specifier in runtime_dependency_names(root):
        if name not in base_names:
            findings.append(
                {
                    "blocking": True,
                    "kind": "runtime_dep_missing_from_requirements",
                    "name": name,
                    "specifier": specifier,
                }
            )
    for item in requirements:
        if not item.specifier:
            findings.append(
                {
                    "blocking": True,
                    "kind": "unspecified",
                    "name": item.name,
                    "specifier": "",
                    "source": item.source,
                }
            )
        elif item.exact_version is None:
            findings.append(
                {
                    "blocking": False,
                    "kind": "unpinned",
                    "name": item.name,
                    "specifier": item.specifier,
                    "source": item.source,
                }
            )
    sbom = build_sbom(root, timestamp="1970-01-01T00:00:00+00:00")
    sbom_names = {component["name"] for component in sbom["components"]}
    for name, specifier in runtime_dependency_names(root):
        if name not in sbom_names:
            findings.append(
                {
                    "blocking": True,
                    "kind": "sbom_missing_runtime_dep",
                    "name": name,
                    "specifier": specifier,
                }
            )
    blocking = [item for item in findings if item["blocking"]]
    return {
        "ok": not blocking,
        "blocking_count": len(blocking),
        "findings": findings,
        "component_count": len(sbom["components"]),
        "note": "Metadata audit only. No vulnerability database was queried.",
        "requirements": len(by_name),
    }
