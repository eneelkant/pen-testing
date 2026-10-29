"""Evidence validation policy for normalized findings.

Scanner output alone never promotes a finding to validated. Primary evidence
must reference the same assessment and in-scope asset, and must not be stale,
summary-only, or contradictory.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .schema import Finding, ValidationStatus, VerificationState

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}


@dataclass(frozen=True)
class EvidenceDecision:
    accepted: bool
    status: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "status": self.status, "reason": self.reason}


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def validate_severity(value: str) -> bool:
    return (value or "").strip().lower() in _VALID_SEVERITIES


def assess_evidence(
    finding: Finding | dict[str, Any],
    *,
    assessment_id: str,
    in_scope_assets: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
    require_primary: bool = True,
    max_age_hours: int = 72,
    now: datetime | None = None,
) -> EvidenceDecision:
    """Return whether evidence can support a human-review promotion.

    Never returns ``validated`` solely because scanner severity is high.
    """
    data = finding.to_dict() if isinstance(finding, Finding) else dict(finding)
    status = str(data.get("validation_status") or ValidationStatus.CANDIDATE.value)
    if status == ValidationStatus.DUPLICATE.value:
        return EvidenceDecision(False, ValidationStatus.DUPLICATE.value, "Finding is marked duplicate")
    if status == ValidationStatus.BLOCKED.value:
        return EvidenceDecision(False, ValidationStatus.BLOCKED.value, "Finding verification is blocked")
    if status == ValidationStatus.REJECTED.value:
        return EvidenceDecision(False, ValidationStatus.REJECTED.value, "Finding was rejected")

    severity = str(data.get("severity") or "").lower()
    if not validate_severity(severity):
        return EvidenceDecision(
            False, ValidationStatus.REJECTED.value, f"Invalid severity value: {severity!r}"
        )

    asset = str(data.get("asset") or "")
    if in_scope_assets is not None and asset:
        normalized_assets = {a.rstrip("/") for a in in_scope_assets}
        # Also accept host-only allowlist entries via exact normalized string forms.
        if asset.rstrip("/") not in normalized_assets and asset not in in_scope_assets:
            return EvidenceDecision(
                False,
                ValidationStatus.BLOCKED.value,
                "Finding asset is out of authorized scope for this assessment",
            )

    payload = evidence if evidence is not None else data.get("evidence_sanitized") or {}
    if not isinstance(payload, dict):
        return EvidenceDecision(
            False, ValidationStatus.REJECTED.value, "Evidence payload must be an object"
        )

    if require_primary:
        if payload.get("summary_only") is True:
            return EvidenceDecision(
                False,
                ValidationStatus.NEEDS_REVIEW.value,
                "Summary-only scanner output is insufficient for validation",
            )
        primary = payload.get("primary") or payload.get("http_exchange") or payload.get("artifact_refs")
        if not primary:
            return EvidenceDecision(
                False,
                ValidationStatus.NEEDS_REVIEW.value,
                "Primary evidence is missing",
            )

    linked = str(payload.get("assessment_id") or data.get("execution_id") or "")
    if assessment_id and linked and linked != assessment_id and linked != data.get("execution_id"):
        # Allow execution_id equality; reject clearly foreign assessment ids.
        if payload.get("assessment_id") and payload.get("assessment_id") != assessment_id:
            return EvidenceDecision(
                False,
                ValidationStatus.REJECTED.value,
                "Evidence assessment_id does not match the current assessment",
            )

    moment = now or datetime.now(timezone.utc)
    evidence_ts = _parse_ts(str(payload.get("captured_at") or data.get("timestamp") or ""))
    if evidence_ts is not None:
        age_hours = (moment - evidence_ts).total_seconds() / 3600.0
        if age_hours > max_age_hours:
            return EvidenceDecision(
                False, ValidationStatus.REJECTED.value, "Evidence is stale for this assessment"
            )

    if payload.get("contradicts_claim") is True:
        return EvidenceDecision(
            False, ValidationStatus.REJECTED.value, "Evidence contradicts the reported claim"
        )

    # High scanner severity still only reaches needs_review — never auto-validated.
    if str(data.get("verification_state")) == VerificationState.HUMAN_CONFIRMED.value:
        return EvidenceDecision(
            True, ValidationStatus.VALIDATED.value, "Human confirmation recorded"
        )

    return EvidenceDecision(
        False,
        ValidationStatus.NEEDS_REVIEW.value,
        "Evidence accepted for human review; scanner severity alone does not validate the finding",
    )


def apply_validation_status(
    finding: Finding,
    decision: EvidenceDecision,
) -> Finding:
    finding.validation_status = decision.status
    if decision.status == ValidationStatus.VALIDATED.value:
        finding.verification_state = VerificationState.HUMAN_CONFIRMED.value
    elif decision.status == ValidationStatus.REJECTED.value:
        finding.verification_state = VerificationState.FALSE_POSITIVE.value
    elif decision.status == ValidationStatus.NEEDS_REVIEW.value:
        finding.verification_state = VerificationState.PARTIAL.value
    elif decision.status == ValidationStatus.BLOCKED.value:
        finding.verification_state = VerificationState.UNVERIFIED.value
    return finding
