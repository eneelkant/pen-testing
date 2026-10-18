"""Local dependency metadata and CycloneDX SBOM generation.

This package records declared requirements. It does not query a vulnerability
database and does not claim that dependencies are free of known CVEs.
"""

from core.supply_chain.audit import audit_dependencies
from core.supply_chain.sbom import build_sbom

__all__ = ["audit_dependencies", "build_sbom"]
