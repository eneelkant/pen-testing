"""Build a CycloneDX SBOM from declared Python requirements."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from core import __version__

_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(.*)$")
_REQUIREMENT_FILES = (
    ("requirements/base.txt", "required"),
    ("requirements/mcp.txt", "optional"),
    ("requirements/dev.txt", "optional"),
)


@dataclass(frozen=True)
class DeclaredRequirement:
    name: str
    specifier: str
    scope: str
    source: str

    @property
    def exact_version(self) -> str | None:
        spec = self.specifier.strip()
        if spec.startswith("==") and not spec.startswith("==="):
            version = spec[2:].strip()
            if version and "*" not in version and "," not in version:
                return version
        return None


def normalize_distribution_name(name: str) -> str:
    """PEP 503 normalization used for comparisons and purls."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement_line(line: str) -> tuple[str, str] | None:
    text = line.split("#", 1)[0].split(";", 1)[0].strip()
    if not text or text.startswith("-"):
        return None
    match = _NAME_RE.match(text)
    if not match:
        return None
    return normalize_distribution_name(match.group(1)), match.group(2).strip()


def _iter_file(
    path: Path,
    scope: str,
    seen: set[Path],
) -> list[DeclaredRequirement]:
    resolved = path.resolve()
    if resolved in seen or not path.is_file():
        return []
    seen.add(resolved)
    found: list[DeclaredRequirement] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.split("#", 1)[0].strip()
        if stripped.startswith(("-r ", "--requirement ")):
            included = (path.parent / stripped.split(None, 1)[1]).resolve()
            found.extend(_iter_file(included, scope, seen))
            continue
        parsed = parse_requirement_line(raw)
        if parsed is None:
            continue
        name, specifier = parsed
        found.append(
            DeclaredRequirement(
                name=name,
                specifier=specifier,
                scope=scope,
                source=str(path),
            )
        )
    return found


def load_requirement_file(path: Path, scope: str) -> list[DeclaredRequirement]:
    return _iter_file(path, scope, set())


def load_requirements(root: Path) -> list[DeclaredRequirement]:
    """Load requirements, preferring required scope and exact pins when duplicated."""
    merged: dict[str, DeclaredRequirement] = {}
    for relative, scope in _REQUIREMENT_FILES:
        path = root / relative
        for item in _iter_file(path, scope, set()):
            current = merged.get(item.name)
            if current is None:
                merged[item.name] = item
                continue
            scope_out = "required" if "required" in {current.scope, item.scope} else item.scope
            chosen = current if current.exact_version else item if item.exact_version else current
            if current.exact_version and item.exact_version and current.exact_version != item.exact_version:
                chosen = current if current.scope == "required" else item
            merged[item.name] = DeclaredRequirement(
                name=item.name,
                specifier=chosen.specifier,
                scope=scope_out,
                source=chosen.source,
            )
    return [merged[name] for name in sorted(merged)]


def runtime_dependency_names(root: Path) -> list[tuple[str, str]]:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", [])
    parsed: list[tuple[str, str]] = []
    for dep in deps:
        item = parse_requirement_line(str(dep))
        if item is None:
            raise ValueError(f"Unparseable project dependency: {dep}")
        parsed.append(item)
    return parsed


def validate_sbom_document(document: dict) -> list[str]:
    """Check the CycloneDX subset this repository emits.

    This is not a certification against the full CycloneDX JSON Schema. It
    rejects documents that claim a vulnerability set they did not generate.
    """
    errors: list[str] = []
    if document.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be CycloneDX")
    if document.get("specVersion") != "1.5":
        errors.append("specVersion must be 1.5")
    if "vulnerabilities" in document:
        errors.append("metadata SBOM must not include a vulnerabilities array")
    meta = document.get("metadata")
    if not isinstance(meta, dict) or not isinstance(meta.get("component"), dict):
        errors.append("metadata.component is required")
    components = document.get("components")
    if not isinstance(components, list) or not components:
        errors.append("components must be a non-empty list")
        return errors
    for component in components:
        name = component.get("name")
        if component.get("type") != "library" or not name or not component.get("purl"):
            errors.append(f"invalid component: {name or component}")
        purl = str(component.get("purl") or "")
        if component.get("version") and "@" not in purl:
            errors.append(f"exact version missing from purl: {name}")
    return errors


def build_sbom(root: Path, *, timestamp: str | None = None) -> dict:
    """Return a CycloneDX 1.5 document for declared requirements.

    The document has no ``vulnerabilities`` array. Absence of that array is not
    a claim that the packages are free of known vulnerabilities.
    """
    generated = timestamp or datetime.now(timezone.utc).isoformat()
    components = []
    for req in load_requirements(root):
        component: dict = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{req.name}",
            "name": req.name,
            "scope": req.scope,
            "purl": f"pkg:pypi/{req.name}",
        }
        exact = req.exact_version
        if exact:
            component["version"] = exact
            component["purl"] = f"pkg:pypi/{req.name}@{exact}"
            component["bom-ref"] = component["purl"]
        if req.specifier and not exact:
            component["properties"] = [
                {"name": "requirement_specifier", "value": req.specifier},
            ]
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": generated,
            "component": {
                "type": "application",
                "name": "pen-testing-platform",
                "version": __version__,
            },
            "properties": [
                {
                    "name": "sbom:source",
                    "value": "declared requirements/*.txt; not a vulnerability scan",
                }
            ],
        },
        "components": components,
    }
