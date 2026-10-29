"""Normalized security finding schema and lifecycle states."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class FindingLifecycle(str, Enum):
    CANDIDATE = "candidate"
    EVIDENCE_COLLECTED = "evidence_collected"
    REPRODUCED = "reproduced"
    HUMAN_REVIEWED = "human_reviewed"
    REPORT_DRAFTED = "report_drafted"
    SUBMITTED = "submitted"
    RESOLVED = "resolved"


class VerificationState(str, Enum):
    UNVERIFIED = "unverified"
    PARTIAL = "partial"
    REPRODUCED = "reproduced"
    FALSE_POSITIVE = "false_positive"
    HUMAN_CONFIRMED = "human_confirmed"


class ValidationStatus(str, Enum):
    """Operator-facing validation gate used by Zoho-workflow reporting.

    Distinct from ``VerificationState`` / ``FindingLifecycle``. Scanner output
    starts as ``candidate`` and must never jump to ``validated`` without human
    confirmation and accepted primary evidence.
    """

    CANDIDATE = "candidate"
    NEEDS_REVIEW = "needs_review"
    VALIDATED = "validated"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    BLOCKED = "blocked"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    """Normalized finding shared across Shannon, Briar, and scanners."""

    title: str
    category: str
    source_tool: str
    source_tool_version: str = "unknown"
    finding_id: str = field(default_factory=lambda: str(uuid4()))
    program: str = ""
    asset: str = ""
    verification_state: str = VerificationState.UNVERIFIED.value
    validation_status: str = ValidationStatus.CANDIDATE.value
    confidence: str = "low"
    lifecycle: str = FindingLifecycle.CANDIDATE.value
    preconditions: list[str] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    evidence_sanitized: dict[str, Any] = field(default_factory=dict)
    expected_behavior: str = ""
    observed_behavior: str = ""
    impact: str = ""
    severity: str = "info"
    severity_rationale: str = ""
    remediation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    related_finding_ids: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utcnow)
    execution_id: str = ""
    assessment_id: str = ""
    raw_refs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


FINDING_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "NormalizedSecurityFinding",
    "type": "object",
    "required": [
        "finding_id",
        "title",
        "category",
        "source_tool",
        "verification_state",
        "lifecycle",
        "severity",
        "timestamp",
    ],
    "properties": {
        "finding_id": {"type": "string", "minLength": 1},
        "title": {"type": "string", "minLength": 1},
        "category": {"type": "string"},
        "source_tool": {"type": "string"},
        "source_tool_version": {"type": "string"},
        "program": {"type": "string"},
        "asset": {"type": "string"},
        "verification_state": {
            "type": "string",
            "enum": [e.value for e in VerificationState],
        },
        "validation_status": {
            "type": "string",
            "enum": [e.value for e in ValidationStatus],
        },
        "confidence": {"type": "string"},
        "lifecycle": {
            "type": "string",
            "enum": [e.value for e in FindingLifecycle],
        },
        "preconditions": {"type": "array", "items": {"type": "string"}},
        "reproduction_steps": {"type": "array", "items": {"type": "string"}},
        "evidence_sanitized": {"type": "object"},
        "expected_behavior": {"type": "string"},
        "observed_behavior": {"type": "string"},
        "impact": {"type": "string"},
        "severity": {"type": "string"},
        "severity_rationale": {"type": "string"},
        "remediation": {"type": "array", "items": {"type": "string"}},
        "references": {"type": "array", "items": {"type": "string"}},
        "related_finding_ids": {"type": "array", "items": {"type": "string"}},
        "timestamp": {"type": "string"},
        "execution_id": {"type": "string"},
        "assessment_id": {"type": "string"},
        "raw_refs": {"type": "object"},
    },
    "additionalProperties": True,
}
