"""Evidence quality gates for normalized findings.

Scanner severity alone never promotes a candidate to a validated finding.
Human confirmation remains a separate lifecycle step.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from core.findings.redaction import redact_secrets
from core.findings.schema import Finding, FindingLifecycle, VerificationState


class EvidenceValidationStatus(str, Enum):
    CANDIDATE = "candidate"
    NEEDS_REVIEW = "needs_review"
    VALIDATED = "validated"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    BLOCKED = "blocked"


_AUTOMATIC_VALIDATED_BLOCKLIST = {
    VerificationState.HUMAN_CONFIRMED.value,
    "validated",
}


@dataclass(frozen=True)
class EvidenceContext:
    assessment_id: str
    approved_target: str
    source_tool: str
    source_tool_version: str = "unknown"
    allowed_account_ids: tuple[str, ...] = ()
    known_finding_fingerprints: tuple[str, ...] = ()


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def finding_fingerprint(finding: Finding | dict[str, Any]) -> str:
    data = finding.to_dict() if isinstance(finding, Finding) else dict(finding)
    parts = [
        str(data.get("title") or "").strip().lower(),
        str(data.get("category") or "").strip().lower(),
        str(data.get("asset") or "").strip().lower(),
        str(data.get("source_tool") or "").strip().lower(),
    ]
    return "|".join(parts)


def validate_finding_evidence(
    finding: Finding | dict[str, Any],
    context: EvidenceContext,
) -> dict[str, Any]:
    """Return a validation decision. Never auto-sets human_confirmed."""
    data = redact_secrets(finding.to_dict() if isinstance(finding, Finding) else dict(finding))
    reasons: list[str] = []
    status = EvidenceValidationStatus.CANDIDATE

    assessment_ref = str(data.get("execution_id") or data.get("assessment_id") or "").strip()
    if context.assessment_id and assessment_ref and assessment_ref != context.assessment_id:
        status = EvidenceValidationStatus.BLOCKED
        reasons.append("Finding assessment/execution id does not match the current assessment")

    asset = str(data.get("asset") or "").strip()
    if context.approved_target and asset:
        approved_host = _host(context.approved_target)
        asset_host = _host(asset) if "://" in asset else asset.lower()
        if approved_host and asset_host and approved_host != asset_host:
            status = EvidenceValidationStatus.BLOCKED
            reasons.append("Finding asset host is outside the approved target")
        elif asset.rstrip("/") != context.approved_target.rstrip("/") and not (
            approved_host and asset_host and approved_host == asset_host
        ):
            # Same host with different path is needs_review, not auto-validated.
            if status == EvidenceValidationStatus.CANDIDATE:
                status = EvidenceValidationStatus.NEEDS_REVIEW
                reasons.append("Finding asset does not exactly match approved target")

    source_tool = str(data.get("source_tool") or "").strip().lower()
    if context.source_tool and source_tool and source_tool != context.source_tool.lower():
        status = EvidenceValidationStatus.BLOCKED
        reasons.append("Finding source tool does not match the assessment tool")

    if not data.get("title") or not data.get("category"):
        status = EvidenceValidationStatus.REJECTED
        reasons.append("Finding is missing mandatory title or category")

    evidence = data.get("evidence_sanitized") or {}
    if not isinstance(evidence, dict):
        status = EvidenceValidationStatus.REJECTED
        reasons.append("Evidence must be an object after sanitization")
        evidence = {}

    # Cross-account fixture mixing.
    account_ids = set()
    for key in ("account_id", "account", "client_id"):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            account_ids.add(value.strip())
    nested_accounts = evidence.get("accounts")
    if isinstance(nested_accounts, list):
        for item in nested_accounts:
            if isinstance(item, str) and item.strip():
                account_ids.add(item.strip())
    if context.allowed_account_ids and account_ids:
        unexpected = account_ids - set(context.allowed_account_ids)
        if unexpected:
            status = EvidenceValidationStatus.BLOCKED
            reasons.append("Evidence references account identifiers outside the approved synthetic set")
        if len(account_ids) > 1:
            status = EvidenceValidationStatus.BLOCKED
            reasons.append("Evidence combines multiple unrelated account identifiers")

    fingerprint = finding_fingerprint(data)
    if fingerprint in set(context.known_finding_fingerprints):
        status = EvidenceValidationStatus.DUPLICATE
        reasons.append("Duplicate finding fingerprint for this assessment")

    # Contradictory or missing proof for authorization-style claims.
    category = str(data.get("category") or "").lower()
    if "authorization" in category or "access-control" in category or "idor" in category:
        expected = str(data.get("expected_behavior") or "").strip()
        observed = str(data.get("observed_behavior") or "").strip()
        if not expected or not observed:
            if status in {EvidenceValidationStatus.CANDIDATE, EvidenceValidationStatus.NEEDS_REVIEW}:
                status = EvidenceValidationStatus.NEEDS_REVIEW
            reasons.append("Authorization findings require expected and observed behavior")
        if expected and observed and expected == observed:
            status = EvidenceValidationStatus.REJECTED
            reasons.append("Expected and observed behavior are identical; no authorization failure demonstrated")

    # Scanner severity must not auto-validate.
    if str(data.get("verification_state") or "") in _AUTOMATIC_VALIDATED_BLOCKLIST:
        # Downgrade automatic promotion attempts.
        data["verification_state"] = VerificationState.UNVERIFIED.value
        if status == EvidenceValidationStatus.CANDIDATE:
            status = EvidenceValidationStatus.NEEDS_REVIEW
        reasons.append("Scanner or import attempted automatic human validation; downgraded")

    if str(data.get("lifecycle") or "") == FindingLifecycle.SUBMITTED.value:
        status = EvidenceValidationStatus.BLOCKED
        reasons.append("Automated submission lifecycle is not permitted")

    if status == EvidenceValidationStatus.CANDIDATE and evidence and data.get("severity"):
        # Presence of sanitized evidence only moves to needs_review, never validated.
        status = EvidenceValidationStatus.NEEDS_REVIEW
        reasons.append("Evidence present; human review required before validation")

    if status == EvidenceValidationStatus.VALIDATED:
        # Defensive: this function never returns validated automatically.
        status = EvidenceValidationStatus.NEEDS_REVIEW
        reasons.append("Automatic validation is refused")

    return {
        "ok": status not in {
            EvidenceValidationStatus.REJECTED,
            EvidenceValidationStatus.BLOCKED,
            EvidenceValidationStatus.DUPLICATE,
        },
        "validation_status": status.value,
        "reasons": reasons,
        "fingerprint": fingerprint,
        "redaction_status": "redacted",
        "finding": data,
        "note": "Severity from a scanner never promotes a finding to validated or human_confirmed.",
    }
