"""Finding normalization and schema validation."""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator

from .redaction import redact_secrets
from .schema import FINDING_JSON_SCHEMA, Finding, FindingLifecycle, VerificationState

_VALIDATOR = Draft202012Validator(FINDING_JSON_SCHEMA)


def validate_finding(data: dict[str, Any]) -> list[str]:
    """Return a list of validation error messages (empty if valid)."""
    errors = sorted(_VALIDATOR.iter_errors(data), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in err.path) or '<root>'}: {err.message}" for err in errors]


def normalize_generic_finding(
    *,
    title: str,
    category: str,
    source_tool: str,
    source_tool_version: str = "unknown",
    asset: str = "",
    program: str = "",
    severity: str = "info",
    evidence: dict[str, Any] | None = None,
    reproduction_steps: list[str] | None = None,
    remediation: list[str] | None = None,
    references: list[str] | None = None,
    execution_id: str = "",
    verification_state: str = VerificationState.UNVERIFIED.value,
    lifecycle: str = FindingLifecycle.CANDIDATE.value,
    confidence: str = "low",
    raw_refs: dict[str, Any] | None = None,
    impact: str = "",
    severity_rationale: str = "",
    expected_behavior: str = "",
    observed_behavior: str = "",
) -> Finding:
    """Build a sanitized normalized Finding from generic scanner output."""
    finding = Finding(
        title=title,
        category=category,
        source_tool=source_tool,
        source_tool_version=source_tool_version,
        asset=asset,
        program=program,
        severity=severity.lower(),
        evidence_sanitized=redact_secrets(evidence or {}),
        reproduction_steps=reproduction_steps or [],
        remediation=remediation or [],
        references=references or [],
        execution_id=execution_id,
        verification_state=verification_state,
        lifecycle=lifecycle,
        confidence=confidence,
        raw_refs=redact_secrets(raw_refs or {}),
        impact=impact,
        severity_rationale=severity_rationale,
        expected_behavior=expected_behavior,
        observed_behavior=observed_behavior,
    )
    errors = validate_finding(finding.to_dict())
    if errors:
        raise ValueError("Normalized finding failed schema validation: " + "; ".join(errors))
    return finding
